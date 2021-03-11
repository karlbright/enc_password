extern crate enc_password;
use enc_password::enc_password;

fn main() {
  let key_id = "20";
  let key_version = "10";
  let public_key = "c251eca108fa8c40acd2cad6eda30475fe779d9fd797cbccec654912c84f8a39";
  let password = "foobar";
  let result = enc_password(key_id, key_version, public_key, password);
  println!("{}", result.unwrap());
}
