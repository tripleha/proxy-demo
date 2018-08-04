import asyncio
import socket
import pprint
import traceback
import re
from asyncio import events
# import ssl
# ssl.match_hostname = lambda cert, hostname: True


BUFF = 8*1024
LINE_DIV = bytes("\r\n", "latin-1")
HEADER_DIV = bytes(": ", "latin-1")

connect_q = asyncio.Queue()
server_q = asyncio.Queue()

host_black_list = list()
with open("./host_black_list", encoding="utf-8") as host_black_list_file:
    host_black_list = [l.strip() for l in host_black_list_file if l.strip()]

redirect_dict = dict()
with open("./redirect_list", encoding="utf-8") as redirect_list_file:
    for l in redirect_list_file:
        if l.strip():
            get_l = l.strip().split(" ")
            redirect_dict[get_l[0]] = (get_l[1], int(get_l[2]))


def get_request_info(raw_data):
    """
    解析浏览器请求的请求数据包
    """
    task = {
        "method": "",
        "url": "",
        "version": "",
        "headers": list(),
        "body": b"",
    }
    raw_lines = raw_data.decode("latin-1").split("\r\n")
    step = 0
    for l_index in range(len(raw_lines)):
        line = raw_lines[l_index]
        if step == 0:
            line = line.strip().split()
            task["method"] = line[0]
            task["url"] = line[1]
            task["version"] = line[2]
            step = 1
        elif step == 1:
            if line == "":
                if task["method"] == "POST":
                    step = 2
                else:
                    break
            else:
                task["headers"].append(line)
        elif step == 2:
            task["body"] += b"".join((bytes(l, "latin-1") for l in raw_lines[l_index:]))
            break
    return task


def get_response_info(raw_data):
    """
    解析服务器响应的响应数据包
    """
    recv_info = {
        "status_code": "",
        "phrase": "",
        "version": "",
        "headers": list(),
        "body": b"",
    }
    raw_lines = raw_data.decode("latin-1").split("\r\n")
    step = 0
    for l_index in range(len(raw_lines)):
        line = raw_lines[l_index]
        if step == 0:
            line = line.strip().split()
            recv_info["version"] = line[0]
            recv_info["status_code"] = line[1]
            recv_info["phrase"] = line[2]
            step = 1
        elif step == 1:
            if line == "":
                step = 2
            else:
                recv_info["headers"].append(line)
        elif step == 2:
            recv_info["body"] += b"".join((bytes(l, "latin-1") for l in raw_lines[l_index:]))
            break
    return recv_info


async def manager(reader, writer):
    """
    获取浏览器请求数据
    先获取完整头部
    并将数据和writer加入任务队列
    """
    request_info = {
        "method": "",
        "url": "",
        "version": "",
        "headers": dict(),
    }
    raw_message = bytes()
    ex_data = bytes()
    step = 0
    while True:
        data = await reader.read(BUFF)
        raw_message += data
        ex_data += data
        print("==== manager ======= recv: ", data)
        if len(data) > 0:
            lines = ex_data.split(LINE_DIV)
            if len(lines) > 1:
                for line in lines[:-1]:
                    if step == 0:
                        # 解析请求行
                        line = line.split()
                        request_info["method"] = line[0].decode("latin-1")
                        request_info["url"] = line[1].decode("latin-1")
                        request_info["version"] = line[2].decode("latin-1")
                        step = 1
                    elif step == 1:
                        # 解析请求头部
                        if len(line) > 0:
                            line = line.split(HEADER_DIV, 1)
                            request_info[line[0].decode("latin-1")] = line[1].decode("latin-1")
                        else:
                            step = 2
                            break
                if step == 2:
                    break
                ex_data = lines[-1]
        else:
            break
    if len(raw_message) > 0:
        use_loop = events.get_event_loop()
        rest = rest_handle(raw_message, request_info, reader, writer)
        use_loop.create_task(rest)
    else:
        writer.close()

async def rest_handle(raw_message, request_info, reader, writer):
    """
    manager完成头部解析之后，负责建立相应服务器连接和其他的处理
    """
    try:
        use_loop = events.get_event_loop()
        method = request_info["method"]
        if method not in ("CONNECT", "GET", "POST"):
            raise RuntimeError("Can not handle request function %s !" % method)

        # 获取正确host与port
        host = request_info.get("Host", None)
        if host is None:
            raise RuntimeError("No host found !")

        url = request_info["url"]
        if method == "CONNECT":
            host, port = (l.strip() for l in host.split(":"))
            port = int(port)
            if port == 80:
                use_ssl = None
            else:
                use_ssl = True
        else:
            if url.startswith("https"):
                port = 443
                use_ssl = True
            else:
                port = 80
                use_ssl = None

        # 检查host黑名单
        is_ban_host = False
        for black_host in host_black_list:
            if black_host in host:
                print("==== ban host ======= Host %s in black list !" % host)
                writer.close()
                is_ban_host = True
                break
        if is_ban_host:
            raise RuntimeWarning("Ban host %s !" % host)

        # 检查重定向名单
        if host in redirect_dict:
            real_host, real_port = host, port
            host, port = redirect_dict[host]
            print("============ host %s:%d redirect to %s:%d" % (real_host, real_port, host, port))
            if method == "CONNECT":
                pass
            elif (port == 443 and url.startswith("https")) or port != 443:
                raw_message = raw_message.replace(bytes(real_host, "latin-1"), bytes(host, "latin-1"))
                print("============ redirect raw_message == " , raw_message)
            else:
                host, port = real_host, real_port

        if "127.0.0.1" in host or "localhost" in host or host.startswith("192.168."):
            family=socket.AF_INET
            ip_addr, port = host.split(":")
            port = int(port)
            ip_info = {
                "ip": ip_addr,
                "port": port
            }
        else:
            # 获取IP信息
            ip_info_list = await use_loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            # print("=========== ip info list ================")
            # pprint.pprint(ip_info_list)
            # print("=========== ip info list end line =======")
            ip_info = ip_info_list[0]
            print("=========== ip info ================")
            pprint.pprint(ip_info)
            print("=========== ip info end line =======")
            ip_addr = ip_info[4][0]
            family = ip_info[0]
        # 创建连接
        s_reader, s_writer = await asyncio.open_connection(
            host=ip_addr,
            port=port,
            # ssl=use_ssl,
            family=family,
            proto=socket.IPPROTO_TCP
        )
        use_loop = events.get_event_loop()
        if method == "CONNECT":
            connect_recv = bytes(request_info["version"] + " 200 Connection Established\r\n\r\n", "latin-1")
            print("=========== connect send ====== ", connect_recv)
            writer.write(connect_recv)
            await writer.drain()
            # await connect_q.put((raw_message, request_info, reader, s_writer, s_reader, writer))
        else:
            # 将已经接收的来自浏览器的数据发向服务器(包含头部)
            s_writer.write(raw_message)
            await s_writer.drain()
            # while True:
            #     new_data = await reader.read(BUFF)
            #     raw_message += new_data
            #     print("==== rest ======= recv: ", new_data)
            #     if len(new_data) == 0:
            #         break
            #     else:
            #         s_writer.write(new_data)
            #         await s_writer.drain()
            # await server_q.put((request_info, s_reader, writer))
        use_loop.create_task(server_worker(request_info, s_reader, writer))
        use_loop.create_task(client_worker(raw_message, request_info, reader, s_writer))
    except RuntimeWarning:
        pass
    except:
        print("============ in rest error ==================")
        try:
            print("host: %s:%d" % (host, port))
            pprint.pprint(ip_info)
        except:
            pass
        print(traceback.format_exc())
        print("============ rest error end line ============")
        try:
            if not s_writer.transport.is_closing():
                s_writer.close()
        except:
            pass
        if not writer.transport.is_closing():
            writer.close()


async def client_worker(raw_message, request_info, reader, s_writer):
    """
    接收浏览器数据并发送到相应的服务器
    """
    try:
        while True:
            new_data = await reader.read(BUFF)
            raw_message += new_data
            if len(new_data) == 0:
                break
            print("==== client worker ======= recv: ", new_data)
            s_writer.write(new_data)
            await s_writer.drain()
    except:
        print("============ in client error ==================")
        pprint.pprint(request_info)
        print(traceback.format_exc())
        print("============ client error end line ============")
        if not s_writer.transport.is_closing():
            s_writer.close()

    # print("======= client worker %d start" % worker_id)
    # while True:
    #     try:
    #         raw_message, request_info, reader, s_writer, s_reader, writer = await connect_q.get()
    #     except RuntimeError:
    #         return
    #     try:
    #         is_put = False
    #         while True:
    #             new_data = await reader.read(BUFF)
    #             raw_message += new_data
    #             if len(new_data) == 0:
    #                 if request_info["method"] == "CONNECT":
    #                     await connect_q.put((raw_message, request_info, reader, s_writer, s_reader, writer))
    #                 break
    #             print("==== client %d worker ======= recv: " % worker_id, new_data)
    #             s_writer.write(new_data)
    #             await s_writer.drain()
    #             if not is_put:
    #                 await server_q.put((request_info, s_reader, writer))
    #                 is_put = True
    #     except:
    #         print("============ in client %d error ==================" % worker_id)
    #         pprint.pprint(request_info)
    #         print(traceback.format_exc())
    #         print("============ client %d error end line ============" % worker_id)
    #         if not s_writer.transport.is_closing():
    #             s_writer.close()


async def server_worker(request_info, s_reader, writer):
    """
    接收服务器端响应并发送回浏览器
    """
    try:
        raw_recv_message = bytes()
        while True:
            recv_data = await s_reader.read(BUFF)
            raw_recv_message += recv_data
            if len(recv_data) == 0:
                break
            print("==== server worker ======= recv: ", recv_data)
            writer.write(recv_data)
            await writer.drain()
    except:
        print("============ in server error ==================")
        pprint.pprint(request_info)
        print(traceback.format_exc())
        print("============ server error end line ============")
    finally:
        if not writer.transport.is_closing():
            writer.close()

    # print("======= server worker %d start" % worker_id)
    # while True:
    #     try:
    #         request_info, s_reader, writer = await server_q.get()
    #     except RuntimeError:
    #         return
    #     try:
    #         raw_recv_message = bytes()
    #         while True:
    #             recv_data = await s_reader.read(BUFF)
    #             raw_recv_message += recv_data
    #             if len(recv_data) == 0:
    #                 if request_info["method"] == "CONNECT":
    #                     await server_q.put((request_info, s_reader, writer))
    #                 break
    #             print("==== server %d worker ======= recv: " % worker_id, recv_data)
    #             writer.write(recv_data)
    #             await writer.drain()
    #     except:
    #         print("============ in server %d error ==================" % worker_id)
    #         pprint.pprint(request_info)
    #         print(traceback.format_exc())
    #         print("============ server %d error end line ============" % worker_id)
    #         if not writer.transport.is_closing():
    #             writer.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    core = asyncio.start_server(manager, "127.0.0.1", 8080, loop=loop)
    server = loop.run_until_complete(core)
    print("===================== server start =====================")

    # workers = list()
    # for i in range(16):
    #     loop.create_task(client_worker(i))
    #     loop.create_task(server_worker(i))
        # workers.append(client_worker(i))
        # workers.append(server_worker(i))

    try:
        # loop.run_until_complete(asyncio.wait(workers))
        loop.run_forever()
    except KeyboardInterrupt:
        print("===================== keyboard interrupt stop =====================")

    server.close()
    loop.run_until_complete(server.wait_closed())
    print("===================== server stop =====================")
    loop.close()
    print("===================== event loop close =====================")
