use url::Url;

pub trait Endpoint {
    const PORT: u16;

    fn port() -> u16 {
        Self::PORT
    }

    fn url() -> Url {
        Url::parse( &format!("http://localhost:{}/", Self::PORT) ).unwrap()
    }
}

macro_rules! endpoint {
    ($name: ident, $port: literal) => {
        pub struct $name;
        impl Endpoint for $name {
            const PORT: u16 = $port;
        }
    }
}

endpoint!( V11y, 9091 );
endpoint!( Collectorist, 9919 );
endpoint!( CollectorOsv, 0 ); // does not care
