use lightning_client::settings::Limits;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(crate) enum EndpointPolicy {
    Lnd,
    Cln,
    Bitcoin,
}

pub(crate) fn validate_node_endpoint(
    endpoint: &url::Url,
    limits: &Limits,
    policy: EndpointPolicy,
) -> bool {
    let scheme_allowed = endpoint.scheme() == "https"
        || (matches!(policy, EndpointPolicy::Bitcoin) && endpoint.scheme() == "http");
    scheme_allowed
        && endpoint.host_str().is_some()
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && endpoint.query().is_none()
        && endpoint.fragment().is_none()
        && endpoint.path() == "/"
        && limits.rpc_seconds != 0
        && limits.max_response_bytes != 0
        && (matches!(policy, EndpointPolicy::Bitcoin) || limits.pagination.snapshot_max_items != 0)
        && (!matches!(policy, EndpointPolicy::Lnd) || limits.rpc_seconds <= i32::MAX as u32)
}

pub(crate) fn node_client_builder(limits: &Limits, https_only: bool) -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(u64::from(limits.rpc_seconds)));
    if https_only {
        builder.https_only(true).tls_built_in_root_certs(false)
    } else {
        builder
    }
}

// The callback may consume complete frames, but the budget counts every received byte.
pub(crate) async fn read_bounded_body<E>(
    mut response: reqwest::Response,
    budget: usize,
    exceeded: impl Fn() -> E,
    offline: impl Fn() -> E,
    mut on_chunk: impl FnMut(&mut Zeroizing<Vec<u8>>, usize) -> Result<(), E>,
) -> Result<Zeroizing<Vec<u8>>, E> {
    if response.content_length().is_some_and(|n| n > budget as u64) {
        return Err(exceeded());
    }
    let mut buffer = Zeroizing::new(Vec::new());
    let mut received = 0;
    while let Some(chunk) = response.chunk().await.map_err(|_| offline())? {
        if chunk.len() > budget.saturating_sub(received) {
            return Err(exceeded());
        }
        received += chunk.len();
        buffer.extend_from_slice(&chunk);
        on_chunk(&mut buffer, received)?;
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn endpoint_shapes_and_family_limit_differences_are_preserved() {
        for policy in [
            EndpointPolicy::Lnd,
            EndpointPolicy::Cln,
            EndpointPolicy::Bitcoin,
        ] {
            let valid = |url: &str, limits: &Limits| {
                validate_node_endpoint(&url.parse().unwrap(), limits, policy)
            };
            let limits = Limits::default();
            assert!(valid("https://localhost/", &limits));
            for url in [
                "ftp://localhost/",
                "file:///",
                "https://user@localhost/",
                "https://:password@localhost/",
                "https://localhost/?",
                "https://localhost/#",
                "https://localhost/rpc",
            ] {
                assert!(!valid(url, &limits), "{url}");
            }
            assert!(!valid(
                "https://localhost/",
                &Limits {
                    rpc_seconds: 0,
                    ..limits.clone()
                }
            ));
            assert!(!valid(
                "https://localhost/",
                &Limits {
                    max_response_bytes: 0,
                    ..limits.clone()
                }
            ));
            assert_eq!(
                valid("http://localhost/", &limits),
                matches!(policy, EndpointPolicy::Bitcoin)
            );
            let mut no_items = limits.clone();
            no_items.pagination.snapshot_max_items = 0;
            assert_eq!(
                valid("https://localhost/", &no_items),
                matches!(policy, EndpointPolicy::Bitcoin)
            );
            assert_eq!(
                valid(
                    "https://localhost/",
                    &Limits {
                        rpc_seconds: i32::MAX as u32 + 1,
                        ..limits
                    }
                ),
                !matches!(policy, EndpointPolicy::Lnd)
            );
        }
    }

    async fn read_request(socket: &mut tokio::net::TcpStream) {
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buffer).await.unwrap();
            assert!(n > 0);
            request.extend_from_slice(&buffer[..n]);
        }
    }

    async fn response(wire: &'static [u8]) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request(&mut socket).await;
            socket.write_all(wire).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let response = node_client_builder(&Limits::default(), false)
            .build()
            .unwrap()
            .get(endpoint)
            .send()
            .await
            .unwrap();
        task.await.unwrap();
        response
    }

    #[tokio::test]
    async fn content_length_rejects_before_reading_or_calling_back() {
        let response = response(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n").await;
        let error = read_bounded_body(
            response,
            3,
            || "limit",
            || "offline",
            |_, _| panic!("oversized body was read"),
        )
        .await
        .unwrap_err();
        assert_eq!(error, "limit");
    }

    #[tokio::test]
    async fn exact_budget_retains_body_and_chunked_overflow_uses_supplied_error() {
        for budget in [0, 5, 6, 7] {
            let response = response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n").await;
            let body = read_bounded_body(
                response,
                budget,
                || "custom overflow",
                || "offline",
                |_, _| Ok(()),
            )
            .await;
            if budget < 6 {
                assert_eq!(body.unwrap_err(), "custom overflow");
            } else {
                assert_eq!(&**body.as_ref().unwrap(), b"abcdef");
            }
        }
    }

    #[tokio::test]
    async fn draining_frames_does_not_reset_total_byte_budget() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let (drained, wait_for_drain) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n")
                .await
                .unwrap();
            wait_for_drain.await.unwrap();
            socket.write_all(b"3\r\ndef\r\n0\r\n\r\n").await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let response = node_client_builder(&Limits::default(), false)
            .build()
            .unwrap()
            .get(endpoint)
            .send()
            .await
            .unwrap();
        let mut drained = Some(drained);
        let mut progress = 0;
        let result = read_bounded_body(
            response,
            5,
            || "limit",
            || "offline",
            |buffer, received| {
                assert_eq!(&**buffer, b"abc");
                progress = received;
                buffer.clear();
                drained.take().unwrap().send(()).unwrap();
                Ok(())
            },
        )
        .await;
        assert_eq!(result.unwrap_err(), "limit");
        assert_eq!(progress, 3);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn truncated_body_and_callback_errors_keep_their_own_error() {
        let response = response(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc").await;
        assert_eq!(
            read_bounded_body(response, 6, || "limit", || "offline", |_, _| Ok(()))
                .await
                .unwrap_err(),
            "offline"
        );
        let response = self::response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc").await;
        assert_eq!(
            read_bounded_body(
                response,
                3,
                || "limit",
                || "offline",
                |_, _| Err("invalid frame")
            )
            .await
            .unwrap_err(),
            "invalid frame"
        );
    }

    #[tokio::test]
    async fn builder_disables_redirects_and_rejects_plaintext_when_required() {
        let response = response(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        let client = node_client_builder(&Limits::default(), true)
            .build()
            .unwrap();
        assert!(client
            .get("http://127.0.0.1:1/")
            .send()
            .await
            .unwrap_err()
            .is_builder());
    }
}
