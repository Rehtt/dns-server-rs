use lazy_static::lazy_static;
use regex::Regex;
use std::net::SocketAddr;
use std::net::UdpSocket;
use trust_dns_client::client::AsyncClient;
use trust_dns_client::client::ClientHandle;
use trust_dns_client::op::{Message, MessageType, OpCode};
use trust_dns_client::rr::rdata::A;
use trust_dns_client::rr::{DNSClass, RData, Record, RecordType};
use trust_dns_client::udp::UdpClientStream;

#[tokio::main]
async fn main() {
    // 监听 127.0.0.1:5345
    let addr: SocketAddr = "127.0.0.1:5345".parse().unwrap();
    let socket = UdpSocket::bind(&addr).unwrap();
    println!("DNS server listening on {}", addr);

    loop {
        let mut buf = [0; 512];
        let (size, src) = socket.recv_from(&mut buf).unwrap();

        // 为每个请求启动一个线程进行处理,实现并发
        let socket_clone = socket.try_clone().unwrap();
        tokio::spawn(async move {
            let buf = &mut buf[..size];
            handle_dns_request(&socket_clone, &src, buf).await;
        });
    }
}

async fn handle_dns_request(socket: &UdpSocket, src: &SocketAddr, req_bytes: &[u8]) {
    // 解析请求数据
    let mut req = Message::from_vec(req_bytes).unwrap();

    // 构造响应消息
    let mut resp = Message::new();
    resp.set_id(req.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_authoritative(false);

    // 遍历请求的问题
    for question in req.queries() {
        // 如果是A记录查询
        if question.query_type() == RecordType::A {
            let name = question.name().to_ascii();
            let ip = parse_ip(&name);

            // 如果域名匹配特定模式,直接返回对应IP
            if let Some(ip) = ip {
                let mut record = Record::new();
                record.set_name(question.name().clone());
                record.set_ttl(60);
                record.set_rr_type(RecordType::A);
                record.set_dns_class(DNSClass::IN);
                record.set_data(Some(RData::A(A(ip))));
                resp.add_answer(record);
                continue;
            }
        }

        // 将其他查询请求转发到上游DNS服务器 8.8.8.8
        let client = {
            let conn = UdpClientStream::<tokio::net::UdpSocket>::new("8.8.8.8:53".parse().unwrap());
            let (client, bg) = AsyncClient::connect(conn).await.unwrap();
            tokio::spawn(bg);
            client
        };
        let mut client = client.clone();
        let resp_forward = client
            .query(
                question.name().clone(),
                question.query_class(),
                question.query_type(),
            )
            .await
            .unwrap();

        // 将上游DNS服务器的应答添加到响应中
        for rec in resp_forward.answers() {
            resp.add_answer(rec.clone());
        }
    }

    // 将响应打包并发送
    let resp_bytes = resp.to_vec().unwrap();
    socket.send_to(&resp_bytes, src).unwrap();
}

// 匹配类似：1.1.1.1.domain.com 的特殊域名
lazy_static! {
    static ref IPV4_REGEX: Regex =
        Regex::new(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.([\w-]+\.)+\w+\.$").unwrap();
}

fn parse_ip(name: &str) -> Option<std::net::Ipv4Addr> {
    if let Some(caps) = IPV4_REGEX.captures(name) {
        let mut ip = [0; 4];
        for i in 0..4 {
            ip[i] = caps[i + 1].parse().unwrap();
        }
        return Some(ip.into());
    }
    None
}
