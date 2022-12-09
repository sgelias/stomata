use actix_http::header::{HeaderName, HeaderValue};
use actix_web::{
    dev::Service, error, middleware, web, App, Error, HttpRequest,
    HttpResponse, HttpServer,
};
use awc::Client;
use clap::Parser;
use futures_util::future::FutureExt;
use serde::{Deserialize, Serialize};
use std::{net::ToSocketAddrs, str::FromStr};
use url::Url;

#[derive(clap::Parser, Debug)]
struct CliArguments {
    listen_addr: String,
    listen_port: u16,
    forward_addr: String,
    forward_port: u16,
}

/// This function forwards the request to the client service.
async fn forward(
    req: HttpRequest,
    payload: web::Payload,
    url: web::Data<Url>,
    client: web::Data<Client>,
) -> Result<HttpResponse, Error> {
    // Clone the request URL and its parameters.
    let mut new_url = url.get_ref().clone();
    new_url.set_path(req.uri().path());
    new_url.set_query(req.uri().query());

    println!("new_url: {:?}", new_url);

    // TODO: This forwarded implementation is incomplete as it only handles the
    // TODO: unofficial X-Forwarded-For header but not the official Forwarded
    // TODO: one.
    let forwarded_req = client
        .request_from(new_url.as_str(), req.head())
        .no_decompress();

    let forwarded_req = match req.head().peer_addr {
        Some(addr) => forwarded_req
            .insert_header(("x-forwarded-for", format!("{}", addr.ip()))),
        None => forwarded_req,
    };

    println!("forwarded_req: {:?}", forwarded_req);

    let res = forwarded_req
        .send_stream(payload)
        .await
        .map_err(error::ErrorInternalServerError)?;

    let mut client_resp = HttpResponse::build(res.status());

    // Remove `Connection` as peer
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection#Directives
    for (header_name, header_value) in
        res.headers().iter().filter(|(h, _)| *h != "connection")
    {
        client_resp.insert_header((header_name.clone(), header_value.clone()));
    }

    Ok(client_resp.streaming(res))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Account {
    name: String,
    email: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let args = CliArguments::parse();

    let forward_socket_addr = (args.forward_addr, args.forward_port)
        .to_socket_addrs()?
        .next()
        .expect("given forwarding address was not valid");

    let forward_url = format!("http://{forward_socket_addr}");
    let forward_url = Url::parse(&forward_url).unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(Client::default()))
            .app_data(web::Data::new(forward_url.clone()))
            .wrap(middleware::Logger::default())
            .wrap_fn(|mut req, svc| {
                println!("req.path: {}", req.path());

                let body = Account {
                    name: String::from("name"),
                    email: String::from("email"),
                };

                match req.cookie("Authorization") {
                    None => (),
                    Some(res) => {
                        println!("cookie value: {:?}", res.value());
                    }
                };

                req.headers_mut().insert(
                    HeaderName::from_str("test").unwrap(),
                    HeaderValue::from_str(
                        serde_json::to_string::<Account>(&body)
                            .unwrap()
                            .as_str(),
                    )
                    .unwrap(),
                );

                svc.call(req).map(|res| {
                    println!("response: {:?}", res);
                    res
                })
            })
            .default_service(web::to(forward))
    })
    .bind((args.listen_addr, args.listen_port))?
    .workers(2)
    .run()
    .await
}
