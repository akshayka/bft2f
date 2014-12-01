
/**
 * The first thing to know about are types. The available types in Thrift are:
 *
 *  bool        Boolean, one byte
 *  byte        Signed byte
 *  i16         Signed 16-bit integer
 *  i32         Signed 32-bit integer
 *  i64         Signed 64-bit integer
 *  double      64-bit floating point value
 *  string      String
 *  binary      Blob (byte array)
 *  map<t1,t2>  Map from one type to another
 *  list<t1>    Ordered list of one type
 *  set<t1>     Set of unique elements of one type
 *
 * Did you also notice that Thrift supports C style comments?
 */

struct Sign_In_Cert {
  1: string node_pub_key,
  2: string sig,       
}

struct Auth_Service_Sign_In_Res {
  1: string user_id,
  2: string user_pub_key,
  3: string user_priv_key_enc,
  4: list<Sign_In_Cert> sign_in_certs,
}
struct Auth_Service_Sign_Up_Res {
  1: string user_id,
  2: string user_pub_key,
  3: string user_priv_key_enc,
}


service Auth_Service  {
    Auth_Service_Sign_In_Res sign_in(1:string user_id, 2:string token),
    Auth_Service_Sign_Up_Res sign_up(1:string user_id, 2:string user_pub_key, 3:string user_priv_key_enc),

}
