use anyhow::{Context, Result};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub async fn send_put_request<T: serde::Serialize>(
    socket_path: &Path,
    endpoint: &str,
    body: &T,
) -> Result<String> {
    let body_str =
        serde_json::to_string(body).context("Failed to serialize request body to JSON")?;

    // Connect to the Unix socket
    let stream = UnixStream::connect(socket_path)
        .await
        .context("Failed to connect to Firecracker socket")?;

    let (read_half, mut write_half) = stream.into_split();

    // Build the raw HTTP PUT request
    let http_request = format!(
        "PUT {} HTTP/1.1\r\n\
           Host: localhost\r\n\
           Content-Type: application/json\r\n\
           Content-Length: {}\r\n\
           \r\n\
           {}",
        endpoint,
        body_str.len(),
        body_str
    );

    // Send the request
    write_half
        .write_all(http_request.as_bytes())
        .await
        .context("Failed to write HTTP request")?;

    // Read response using BufReader
    let mut reader = BufReader::new(read_half);
    let mut response = String::new();
    let mut content_length: Option<usize> = None;

    // Read status line
    reader.read_line(&mut response).await?;

    // Read headers until empty line
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        // Check for Content-Length
        if line.to_lowercase().starts_with("content-length:") {
            if let Some(len_str) = line.split(":").nth(1) {
                content_length = len_str.trim().parse().ok();
            }
        }

        response.push_str(&line);

        // Empty line signals end of headers
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    // Read body if Content-Length is present
    if let Some(len) = content_length {
        let mut body_buf = vec![0u8; len];
        reader.read_exact(&mut body_buf).await?;
        response.push_str(&String::from_utf8_lossy(&body_buf));
    }

    Ok(response)
}

pub async fn send_patch_request<T: serde::Serialize>(
    socket_path: &Path,
    endpoint: &str,
    body: &T,
) -> Result<String> {
    let body_str =
        serde_json::to_string(body).context("Failed to serialize request body to JSON")?;

    // Connect to the Unix socket
    let stream = UnixStream::connect(socket_path)
        .await
        .context("Failed to connect to Firecracker socket")?;

    let (read_half, mut write_half) = stream.into_split();

    // Build the raw HTTP PATCH request
    let http_request = format!(
        "PATCH {} HTTP/1.1\r\n\
           Host: localhost\r\n\
           Content-Type: application/json\r\n\
           Content-Length: {}\r\n\
           \r\n\
           {}",
        endpoint,
        body_str.len(),
        body_str
    );

    // Send the request
    write_half
        .write_all(http_request.as_bytes())
        .await
        .context("Failed to write HTTP request")?;

    // Read response using BufReader
    let mut reader = BufReader::new(read_half);
    let mut response = String::new();
    let mut content_length: Option<usize> = None;

    // Read status line
    reader.read_line(&mut response).await?;

    // Read headers until empty line
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        // Check for Content-Length
        if line.to_lowercase().starts_with("content-length:") {
            if let Some(len_str) = line.split(":").nth(1) {
                content_length = len_str.trim().parse().ok();
            }
        }

        response.push_str(&line);

        // Empty line signals end of headers
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    // Read body if Content-Length is present
    if let Some(len) = content_length {
        let mut body_buf = vec![0u8; len];
        reader.read_exact(&mut body_buf).await?;
        response.push_str(&String::from_utf8_lossy(&body_buf));
    }

    Ok(response)
}
