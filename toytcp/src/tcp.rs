use crate::packet::TCPPacket;
use crate::socket::{SockID, Socket, TcpStatus};
use crate::tcp_flags;
use anyhow::{Context, Result};
use pnet::packet::{ip::IpNextHeaderProtocols, tcp::TcpPacket, Packet};
use pnet::transport::{self, TransportChannelType};
use rand::{rngs::ThreadRng, Rng};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex, RwLock, RwLockWriteGuard};
use std::time::{Duration, SystemTime};
use std::{cmp, ops::Range, str, thread};

const UNDETERMINED_IP_ADDR: std::net::Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const UNDETERMINED_PORT: u16 = 0;
const MAX_TRANSMITTION: u8 = 5;
const RETRANSMITTION_TIMEOUT: u64 = 3;
const MSS: usize = 1460;
const PORT_RANGE: Range<u16> = 40000..60000;

pub struct TCP {
    sockets: RwLock<HashMap<SockID, Socket>>,
    event_condvar: (Mutex<Option<TCPEvent>>, Condvar),
}

#[derive(Debug, Clone, PartialEq)]
struct TCPEvent {
    sock_id: SockID,
    kind: TCPEventKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TCPEventKind {
    ConnectionCompleted,
    Acked,
    DataArrived,
    ConnectionClosed,
}

impl TCPEvent {
    fn new(sock_id: SockID, kind: TCPEventKind) -> Self {
        Self { sock_id, kind }
    }
}

impl TCP {
    pub fn new() -> Arc<Self> {
        let sockets = RwLock::new(HashMap::new());
        let tcp = Arc::new(Self {
            sockets,
            event_condvar: (Mutex::new(None), Condvar::new()),
        });
        let cloned_tcp = tcp.clone();
        std::thread::spawn(move || {
            cloned_tcp.receive_handler().unwrap();
        });
        let cloned_tcp = tcp.clone();
        std::thread::spawn(move || {
            cloned_tcp.timer();
        });
        tcp
    }

    // 再送キューを見てタイムアウトしているpacketを再送する
    fn timer(&self) {
        dbg!("begin timer thread");
        loop {
            // socket一覧持ってくる
            let mut table = self.sockets.write().unwrap();
            for (sock_id, socket) in table.iter_mut() {
                // socketの再送queueのitemについて
                while let Some(mut item) = socket.retransmission_queue.pop_front() {
                    // ackされてたら何もしなくていい(queueから排除)
                    if socket.send_param.unacked_seq > item.packet.get_seq() {
                        dbg!("successfully acked", item.packet.get_seq());
                        socket.send_param.window += item.packet.payload().len() as u16;
                        self.publish_event(*sock_id, TCPEventKind::Acked);
                        if item.packet.get_flag() & tcp_flags::FIN > 0
                            && socket.status == TcpStatus::LastAck
                        {
                            self.publish_event(*sock_id, TCPEventKind::ConnectionClosed);
                        }
                        continue;
                    }
                    // 再送期限よりも前だったら先頭に戻す
                    if item.latest_transmission_time.elapsed().unwrap()
                        < Duration::from_secs(RETRANSMITTION_TIMEOUT)
                    {
                        socket.retransmission_queue.push_front(item);
                        break;
                    }
                    // 再送回数以内だったら
                    if item.transmission_count < MAX_TRANSMITTION {
                        dbg!("retransmit");
                        // 再送
                        socket
                            .sender
                            .send_to(item.packet.clone(), IpAddr::V4(socket.remote_addr))
                            .context("failed to retransmit")
                            .unwrap();
                        // queueに戻す
                        item.transmission_count += 1;
                        item.latest_transmission_time = SystemTime::now();
                        socket.retransmission_queue.push_back(item);
                        break;
                    } else {
                        dbg!("reached MAX_TRANSMITTION");
                        if item.packet.get_flag() & tcp_flags::FIN > 0
                            && (socket.status == TcpStatus::LastAck
                                || socket.status == TcpStatus::FinWait1
                                || socket.status == TcpStatus::FinWait2)
                        {
                            self.publish_event(*sock_id, TCPEventKind::ConnectionClosed);
                        }
                    }
                }
            }
            drop(table);
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn select_unused_port(&self, rng: &mut ThreadRng) -> Result<u16> {
        for _ in 0..(PORT_RANGE.end - PORT_RANGE.start) {
            let local_port = rng.gen_range(PORT_RANGE);
            let table = self.sockets.read().unwrap();
            if table.keys().all(|k| local_port != k.2) {
                return Ok(local_port);
            }
        }
        anyhow::bail!("no available port found.");
    }

    fn process_payload(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        // 読み込んだペイロードが書き込まれる先頭位置
        // socket.recv_buffer.len() - socket.recv_param.window => 受信バッファにすでに入っているデータの一番後ろ
        // packet.get_seq() - socket.recv_param.next => パケットのseq - 次に来る想定のseq => パケットがとんでいたら0以上になる
        // offset => パケットが飛んでいなければ前回データの最後、飛んでいたらそれより先に指定される
        let offset = socket.recv_buffer.len() - socket.recv_param.window as usize
            + (packet.get_seq() - socket.recv_param.next) as usize;
        // copyするサイズはデータ長と{(受信バッファ - offset) => 受信バッファに入れられる限界量}の小さい方
        let copy_size = cmp::min(packet.payload().len(), socket.recv_buffer.len() - offset);
        // 受信バッファにコピー
        socket.recv_buffer[offset..offset + copy_size]
            .copy_from_slice(&packet.payload()[..copy_size]);
        // tailを更新
        // ロス再送の際穴埋めされるために現在の末尾とseq + 受信サイズの大きい方にする
        socket.recv_param.tail =
            cmp::max(socket.recv_param.tail, packet.get_seq() + copy_size as u32);

        if packet.get_seq() == socket.recv_param.next {
            // 順序入れ替わり無しの場合のみrecv_param.nextを進められる
            socket.recv_param.next = socket.recv_param.tail;
            // windowを読み込み量分開ける
            socket.recv_param.window -= (socket.recv_param.tail - packet.get_seq()) as u16;
        }
        if copy_size > 0 {
            // 受信バッファにコピーが成功
            socket.send_tcp_packet(
                socket.send_param.next,
                socket.recv_param.next,
                tcp_flags::ACK,
                &[],
            )?;
        } else {
            // 受信バッファが溢れた時はセグメントを破棄
            dbg!("recv buffer overflow");
        }
        self.publish_event(socket.get_sock_id(), TCPEventKind::DataArrived);
        Ok(())
    }

    fn receive_handler(&self) -> Result<()> {
        dbg!("begin recv thread");
        let (_, mut receiver) = transport::transport_channel(
            65535,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
        )
        .unwrap();
        let mut packet_iter = transport::ipv4_packet_iter(&mut receiver);
        loop {
            // packet作成
            let (packet, remote_addr) = match packet_iter.next() {
                Ok((p, r)) => (p, r),
                Err(_) => continue,
            };
            let local_addr = packet.get_destination();
            // TcpPacketに変換
            let tcp_packet = match TcpPacket::new(packet.payload()) {
                Some(p) => p,
                None => continue,
            };
            // TCPPacketに変換
            let packet = TCPPacket::from(tcp_packet);
            // remote_addr取得
            let remote_addr = match remote_addr {
                IpAddr::V4(addr) => addr,
                _ => continue,
            };
            // socket一覧取得
            let mut table = self.sockets.write().unwrap();
            // すでにsocketがあったらそれを返す
            let socket = match table.get_mut(&SockID(
                local_addr,
                remote_addr,
                packet.get_dest(),
                packet.get_src(),
            )) {
                Some(socket) => socket,
                None => match table.get_mut(&SockID(
                    local_addr,
                    UNDETERMINED_IP_ADDR,
                    packet.get_dest(),
                    UNDETERMINED_PORT,
                )) {
                    Some(socket) => socket,
                    None => continue,
                },
            };
            if !packet.is_correct_checksum(local_addr, remote_addr) {
                dbg!("invalid checksum");
                continue;
            }
            let sock_id = socket.get_sock_id();
            if let Err(error) = match socket.status {
                // synsentの場合
                TcpStatus::Listen => self.listen_handler(table, sock_id, &packet, remote_addr),
                TcpStatus::SynRcvd => self.synrcvd_handler(table, sock_id, &packet),
                TcpStatus::SynSent => self.synsent_handler(socket, &packet),
                TcpStatus::Established => self.established_handler(socket, &packet),
                TcpStatus::CloseWait | TcpStatus::LastAck => self.close_handler(socket, &packet),
                TcpStatus::FinWait1 | TcpStatus::FinWait2 => self.finwait_handler(socket, &packet),
                _ => {
                    dbg!("not implemented state");
                    Ok(())
                }
            } {
                dbg!(error);
            }
        }
    }

    fn synsent_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        dbg!("synsent handler");
        // packetがACK|SYN && packetのackがunackedとnextの間にあることを確認
        if packet.get_flag() & tcp_flags::ACK > 0
            && socket.send_param.unacked_seq <= packet.get_ack()
            && packet.get_ack() <= socket.send_param.next
            && packet.get_flag() & tcp_flags::SYN > 0
        {
            // 受信側: nextをpacketのseq+1に、initial_seqをpacketのseqに設定
            socket.recv_param.next = packet.get_seq() + 1;
            socket.recv_param.initial_seq = packet.get_seq();
            // 送信側: unackedをpacketのackに、windowをpacketのwindow_sizeに設定
            socket.send_param.unacked_seq = packet.get_ack();
            socket.send_param.window = packet.get_window_size();
            // 送信側: unackedがinitialより大きかったら接続完了としてACKを送信
            if socket.send_param.unacked_seq > socket.send_param.initial_seq {
                // Establishedにする
                socket.status = TcpStatus::Established;
                // seqにsend_param.next(次に送信するseq)、ackにrecv_param.next(受け取ったpacketのseq+1)を設定して送信
                socket.send_tcp_packet(
                    socket.send_param.next,
                    socket.recv_param.next,
                    tcp_flags::ACK,
                    &[],
                )?;
                dbg!("status: synsent ->", &socket.status);
                // 接続完了イベントを発行
                self.publish_event(socket.get_sock_id(), TCPEventKind::ConnectionCompleted);
            } else {
                socket.status = TcpStatus::SynRcvd;
                socket.send_tcp_packet(
                    socket.send_param.next,
                    socket.recv_param.next,
                    tcp_flags::ACK,
                    &[],
                )?;
                dbg!("status: synsent ->", &socket.status);
            }
        }
        Ok(())
    }

    fn listen_handler(
        &self,
        mut table: RwLockWriteGuard<HashMap<SockID, Socket>>,
        listening_socket_id: SockID,
        packet: &TCPPacket,
        remote_addr: Ipv4Addr,
    ) -> Result<()> {
        dbg!("listen handler");
        if packet.get_flag() & tcp_flags::ACK > 0 {
            return Ok(());
        }
        let listening_socket = table.get_mut(&listening_socket_id).unwrap();
        if packet.get_flag() & tcp_flags::SYN > 0 {
            // passive open実施
            let mut connection_socket = Socket::new(
                listening_socket.local_addr,
                remote_addr,
                listening_socket.local_port,
                packet.get_src(),
                TcpStatus::SynRcvd,
            )?;
            connection_socket.recv_param.next = packet.get_seq() + 1;
            connection_socket.recv_param.initial_seq = packet.get_seq();
            connection_socket.send_param.initial_seq = rand::thread_rng().gen_range(1..1 << 31);
            connection_socket.send_param.window = packet.get_window_size();
            connection_socket.send_tcp_packet(
                connection_socket.send_param.initial_seq,
                connection_socket.recv_param.next,
                tcp_flags::SYN | tcp_flags::ACK,
                &[],
            )?;
            connection_socket.send_param.next = connection_socket.send_param.initial_seq + 1;
            connection_socket.send_param.unacked_seq = connection_socket.send_param.initial_seq;
            connection_socket.listening_socket = Some(listening_socket.get_sock_id());
            dbg!("status: listen -> ", &connection_socket.status);
            table.insert(connection_socket.get_sock_id(), connection_socket);
        }
        Ok(())
    }

    fn synrcvd_handler(
        &self,
        mut table: RwLockWriteGuard<HashMap<SockID, Socket>>,
        sock_id: SockID,
        packet: &TCPPacket,
    ) -> Result<()> {
        dbg!("synrcvd handler");
        let socket = table.get_mut(&sock_id).unwrap();

        if packet.get_flag() & tcp_flags::ACK > 0
            && socket.send_param.unacked_seq <= packet.get_ack()
            && packet.get_ack() <= socket.send_param.next
        {
            socket.recv_param.next = packet.get_seq();
            socket.send_param.unacked_seq = packet.get_ack();
            socket.status = TcpStatus::Established;
            dbg!("status: synrcvd ->", &socket.status);
            if let Some(id) = socket.listening_socket {
                let ls = table.get_mut(&id).unwrap();
                ls.connected_connection_queue.push_back(sock_id);
                self.publish_event(ls.get_sock_id(), TCPEventKind::ConnectionCompleted);
            }
        }
        Ok(())
    }

    fn wait_event(&self, sock_id: SockID, kind: TCPEventKind) {
        dbg!("start wait for event", &sock_id, &kind);
        let (lock, cvar) = &self.event_condvar;
        let mut event = lock.lock().unwrap();
        loop {
            if let Some(ref e) = *event {
                if e.sock_id == sock_id && e.kind == kind {
                    break;
                }
            }
            event = cvar.wait(event).unwrap();
        }
        dbg!(&event);
        *event = None;
    }

    fn close_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        dbg!("closewait | lastack handler");
        socket.send_param.unacked_seq = packet.get_ack();
        Ok(())
    }

    fn publish_event(&self, sock_id: SockID, kind: TCPEventKind) {
        let (lock, cvar) = &self.event_condvar;
        let mut e = lock.lock().unwrap();
        *e = Some(TCPEvent::new(sock_id, kind));
        cvar.notify_all();
    }

    fn delete_acked_segment_from_retransmission_queue(&self, socket: &mut Socket) {
        dbg!("ack accept", socket.send_param.unacked_seq);
        while let Some(item) = socket.retransmission_queue.pop_front() {
            // 送信側によって確認されてない最古のseq(socket.send_param.unacked_seq)よりpacketのseqが古ければ
            // それはすでにackされているということなので消す
            if socket.send_param.unacked_seq > item.packet.get_seq() {
                dbg!("successfully acked", item.packet.get_seq());
                socket.send_param.window += item.packet.payload().len() as u16;
                self.publish_event(socket.get_sock_id(), TCPEventKind::Acked);
            } else {
                // そうでなかったら`先頭`に戻す(それより後ろのseqもackされてないので)
                socket.retransmission_queue.push_front(item);
                break;
            }
        }
    }

    fn established_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        dbg!("established handler");
        if socket.send_param.unacked_seq < packet.get_ack()
            && packet.get_ack() <= socket.send_param.next
        {
            socket.send_param.unacked_seq = packet.get_ack();
            self.delete_acked_segment_from_retransmission_queue(socket);
        } else if socket.send_param.next < packet.get_ack() {
            // 未送信セグメントに対するackは廃棄
            return Ok(());
        }
        if packet.get_flag() & tcp_flags::ACK == 0 {
            // ACKが立っていないパケットは破棄
            return Ok(());
        }
        if !packet.payload().is_empty() {
            self.process_payload(socket, &packet)?;
        }
        // パッシブクローズ(相手からFIN | ACK)の場合はこっち
        if packet.get_flag() & tcp_flags::FIN > 0 {
            socket.recv_param.next = packet.get_seq() + 1;
            socket.send_tcp_packet(
                socket.send_param.next,
                socket.recv_param.next,
                tcp_flags::ACK,
                &[],
            )?;
            socket.status = TcpStatus::CloseWait;
            self.publish_event(socket.get_sock_id(), TCPEventKind::DataArrived);
        }
        Ok(())
    }

    /// FINWAIT1 or FINWAIT2状態のソケットに到着したパケットの処理
    /// この時はこっちがcloseしたいと言ったけど、向こうがまだクローズしていない状態
    fn finwait_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        dbg!("finwait handler");
        if socket.send_param.unacked_seq < packet.get_ack()
            && packet.get_ack() <= socket.send_param.next
        {
            // ackのものを受け取る
            socket.send_param.unacked_seq = packet.get_ack();
            self.delete_acked_segment_from_retransmission_queue(socket);
        } else if socket.send_param.next < packet.get_ack() {
            // 未送信セグメントに対するackは破棄
            return Ok(());
        }
        if packet.get_flag() & tcp_flags::ACK == 0 {
            // ACKが立っていないパケットは破棄
            return Ok(());
        }
        // payloadがあったら処理
        if !packet.payload().is_empty() {
            self.process_payload(socket, &packet)?;
        }

        // FinWait1だったらFinWait2に移行
        if socket.status == TcpStatus::FinWait1
            && socket.send_param.next == socket.send_param.unacked_seq
        {
            // 送信したFINがackされていればFinWait2へ遷移
            socket.status = TcpStatus::FinWait2;
            dbg!("status: finwait1 ->", &socket.status);
        }

        // FINパケットだったらACKを返す
        if packet.get_flag() & tcp_flags::FIN > 0 {
            // 本来はCLOSING stateも考慮する必要があるが省略
            socket.recv_param.next += 1;
            socket.send_tcp_packet(
                socket.send_param.next,
                socket.recv_param.next,
                tcp_flags::ACK,
                &[],
            )?;
            // ConnectionClosedイベント送信
            self.publish_event(socket.get_sock_id(), TCPEventKind::ConnectionClosed);
        }
        Ok(())
    }

    pub fn connect(&self, addr: Ipv4Addr, port: u16) -> Result<SockID> {
        let mut rng = rand::thread_rng();
        let mut socket = Socket::new(
            get_source_addr_to(addr)?,
            addr,
            self.select_unused_port(&mut rng)?,
            port,
            TcpStatus::SynSent,
        )?;
        socket.send_param.initial_seq = rng.gen_range(1..1 << 31);
        // ここでSYN送ってる(active open)
        socket.send_tcp_packet(socket.send_param.initial_seq, 0, tcp_flags::SYN, &[])?;
        socket.send_param.unacked_seq = socket.send_param.initial_seq;
        socket.send_param.next = socket.send_param.initial_seq + 1;
        let mut table = self.sockets.write().unwrap();
        let sock_id = socket.get_sock_id();
        let _ = table.insert(sock_id, socket);
        drop(table);
        self.wait_event(sock_id, TCPEventKind::ConnectionCompleted);
        Ok(sock_id)
    }

    // listenしているsocketをsocketsに登録する
    pub fn listen(&self, local_addr: Ipv4Addr, local_port: u16) -> Result<SockID> {
        let socket = Socket::new(
            local_addr,
            UNDETERMINED_IP_ADDR,
            local_port,
            UNDETERMINED_PORT,
            TcpStatus::Listen,
        )?;
        let mut lock = self.sockets.write().unwrap();
        let sock_id = socket.get_sock_id();
        lock.insert(sock_id, socket);
        Ok(sock_id)
    }

    // sock_id指定でConnectionCompletedになるまで待つ
    // その後そのsocketに接続済みとなっているsocketのqueueからsocketIDを返す
    pub fn accept(&self, sock_id: SockID) -> Result<SockID> {
        self.wait_event(sock_id, TCPEventKind::ConnectionCompleted);

        let mut table = self.sockets.write().unwrap();
        Ok(table
            .get_mut(&sock_id)
            .context(format!("no such socket: {:?}", sock_id))?
            .connected_connection_queue
            .pop_front()
            .context("no connected socket")?)
    }

    // 全て送信したらackきてなくてもreturnする
    pub fn send(&self, sock_id: SockID, buffer: &[u8]) -> Result<()> {
        let mut cursor = 0;
        while cursor < buffer.len() {
            let mut table = self.sockets.write().unwrap();
            let mut socket = table
                .get_mut(&sock_id)
                .context(format!("no such socket: {:?}", sock_id))?;
            let mut send_size = cmp::min(
                MSS,
                cmp::min(socket.send_param.window as usize, buffer.len() - cursor),
            );
            // sliding windowの幅が残ってない場合
            while send_size == 0 {
                dbg!("unable to slide send window");
                // ACK返ってくるまで待つ
                drop(table);
                self.wait_event(sock_id, TCPEventKind::Acked);
                // 返ってきたら再度socket取得して送信サイズ確認
                table = self.sockets.write().unwrap();
                socket = table
                    .get_mut(&sock_id)
                    .context(format!("no such socket: {:?}", sock_id))?;
                send_size = cmp::min(
                    MSS,
                    cmp::min(socket.send_param.window as usize, buffer.len() - cursor),
                );
            }
            dbg!("current window size", socket.send_param.window);
            socket.send_tcp_packet(
                socket.send_param.next,
                socket.recv_param.next,
                tcp_flags::ACK,
                &buffer[cursor..cursor + send_size],
            )?;
            cursor += send_size;
            socket.send_param.next += send_size as u32;
            socket.send_param.window -= send_size as u16;
            drop(table);
            thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    // データをバッファに読み込んで，読み込んだサイズを返す．FINを読み込んだ場合は0を返す
    // パケットが届くまでブロックする
    pub fn recv(&self, sock_id: SockID, buffer: &mut [u8]) -> Result<usize> {
        let mut table = self.sockets.write().unwrap();
        let mut socket = table
            .get_mut(&sock_id)
            .context(format!("no such socket: {:?}", sock_id))?;
        let mut received_size = socket.recv_buffer.len() - socket.recv_param.window as usize;
        while received_size == 0 {
            // ペイロードを受信 or FINを受信でスキップ
            match socket.status {
                TcpStatus::CloseWait | TcpStatus::LastAck | TcpStatus::TimeWait => break,
                _ => {}
            }
            // ロックを外してイベントの待機．受信スレッドがロックを取得できるようにするため．
            drop(table);
            dbg!("waiting incoming data");
            // establish_handlerにFINが来た場合(パッシブクローズ)もDataArrivedは発行される
            self.wait_event(sock_id, TCPEventKind::DataArrived);
            table = self.sockets.write().unwrap();
            socket = table
                .get_mut(&sock_id)
                .context(format!("no such socket: {:?}", sock_id))?;
            received_size = socket.recv_buffer.len() - socket.recv_param.window as usize;
        }
        let copy_size = cmp::min(buffer.len(), received_size);
        buffer[..copy_size].copy_from_slice(&socket.recv_buffer[..copy_size]);
        // srcの範囲をdestにcopyする
        socket.recv_buffer.copy_within(copy_size.., 0);
        socket.recv_param.window += copy_size as u16;
        Ok(copy_size)
    }

    /// 接続を閉じる．
    pub fn close(&self, sock_id: SockID) -> Result<()> {
        let mut table = self.sockets.write().unwrap();
        let mut socket = table
            .get_mut(&sock_id)
            .context(format!("no such socket: {:?}", sock_id))?;
        // FIN | ACK を送る
        socket.send_tcp_packet(
            socket.send_param.next,
            socket.recv_param.next,
            tcp_flags::FIN | tcp_flags::ACK,
            &[],
        )?;
        socket.send_param.next += 1;
        match socket.status {
            // まだ相手がcloseしていない場合
            TcpStatus::Established => {
                socket.status = TcpStatus::FinWait1;
                // ロックを外してイベントの待機．受信スレッドがロックを取得できるようにするため．
                drop(table);
                self.wait_event(sock_id, TCPEventKind::ConnectionClosed);
                let mut table = self.sockets.write().unwrap();
                table.remove(&sock_id);
                dbg!("closed & removed", sock_id);
            }
            // 相手がすでにcloseしている場合
            TcpStatus::CloseWait => {
                socket.status = TcpStatus::LastAck;
                // ロックを外してイベントの待機．受信スレッドがロックを取得できるようにするため．
                drop(table);
                self.wait_event(sock_id, TCPEventKind::ConnectionClosed);
                let mut table = self.sockets.write().unwrap();
                table.remove(&sock_id);
                dbg!("closed & removed", sock_id);
            }
            TcpStatus::Listen => {
                table.remove(&sock_id);
            }
            _ => return Ok(()),
        }
        Ok(())
    }
}

fn get_source_addr_to(addr: Ipv4Addr) -> Result<Ipv4Addr> {
    let output = Command::new("sh")
        .args(["-c"])
        .args([format!("ip route get {} | grep src", addr)])
        .output()?;
    let mut output = str::from_utf8(&output.stdout)?
        .trim()
        .split_ascii_whitespace();
    while let Some(s) = output.next() {
        if s == "src" {
            break;
        }
    }
    let ip = output.next().context("failed to get src ip")?;
    dbg!("source addr", ip);
    ip.parse().context("failed to parse source ip")
}
