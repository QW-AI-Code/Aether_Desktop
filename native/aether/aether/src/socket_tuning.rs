//! Shared UDP budgets, including Windows socket handles.
use tokio::net::UdpSocket;
pub fn tune_udp_buffers(socket: &UdpSocket) {
    let want_rcv = crate::sysprofile::udp_socket_rcv_buf_bytes();
    let want_snd = crate::sysprofile::udp_socket_snd_buf_bytes();

    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, BorrowedFd};
        // Safe: `socket` owns the descriptor and outlives this borrow.
        let borrowed = unsafe { BorrowedFd::borrow_raw(socket.as_raw_fd()) };
        let reference = socket2::SockRef::from(&borrowed);
        let _ = reference.set_recv_buffer_size(want_rcv);
        let _ = reference.set_send_buffer_size(want_snd);

        // A kernel that refuses to shrink the send buffer restores the r6 root
        // cause in full silence, so it is not allowed to be silent. `wmem_min`
        // and a doubled report are both normal; three times the request is not.
        if let Ok(applied) = reference.send_buffer_size() {
            if applied > want_snd.saturating_mul(3) {
                log::warn!(
                    "[-] the kernel kept SO_SNDBUF at {}KB although {}KB was requested; the \
                     uplink queue is NOT bounded on this device and the congestion controller \
                     will not see backpressure. Send this log.",
                    applied / 1024,
                    want_snd / 1024,
                );
            }
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket, BorrowedSocket};
        let borrowed=unsafe {BorrowedSocket::borrow_raw(socket.as_raw_socket())};
        let reference=socket2::SockRef::from(&borrowed);
        let _=reference.set_recv_buffer_size(want_rcv);
        let _=reference.set_send_buffer_size(want_snd);
    }
    #[cfg(not(any(unix,windows)))] {let _=(socket,want_rcv,want_snd);}
}

/// The `SO_SNDBUF` the kernel actually granted, in KB (0 when unknown).
///
/// Reported once per uplink telemetry window by the WireGuard writer, because
/// this number is the difference between a bounded uplink and the r5 build.
pub fn send_buffer_kb(socket: &UdpSocket) -> usize {
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, BorrowedFd};
        let borrowed = unsafe { BorrowedFd::borrow_raw(socket.as_raw_fd()) };
        let reference = socket2::SockRef::from(&borrowed);
        reference
            .send_buffer_size()
            .map(|b| b / 1024)
            .unwrap_or(0)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket,BorrowedSocket};
        let borrowed=unsafe {BorrowedSocket::borrow_raw(socket.as_raw_socket())};
        socket2::SockRef::from(&borrowed).send_buffer_size().map(|b|b/1024).unwrap_or(0)
    }
    #[cfg(not(any(unix,windows)))] {let _=socket;0}
}
