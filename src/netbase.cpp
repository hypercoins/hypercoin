// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netbase.h>

#include <hash.h>
#include <sync.h>
#include <uint256.h>
#include <random.h>
#include <util.h>
#include <utilstrencodings.h>

#include <atomic>

#ifndef WIN32
#include <fcntl.h>
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()

#if !defined(HAVE_MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

// Settings
static proxyType proxyInfo[NET_MAX];
static proxyType nameProxy;
static CCriticalSection cs_proxyInfos;
int nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;
bool fNameLookup = DEFAULT_NAME_LOOKUP;

// Need ample time for negotiation for very slow proxies such as Tor (milliseconds)
static const int SOCKS5_RECV_TIMEOUT = 20 * 1000;
static std::atomic<bool> interruptSocks5Recv(false);

enum Network ParseNetwork(std::string net) {
    boost::to_lower(net);
    if (net == "ipv4") return NET_IPV4;
    if (net == "ipv6") return NET_IPV6;
    if (net == "tor" || net == "onion")  return NET_TOR;
    return NET_UNROUTABLE;
}

std::string GetNetworkName(enum Network net) {
    switch(net)
    {
    case NET_IPV4: return "ipv4";
    case NET_IPV6: return "ipv6";
    case NET_TOR: return "onion";
    default: return "";
    }
}

bool static LookupIntern(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
{
    vIP.clear();

    {
        CNetAddr addr;
        if (addr.SetSpecial(std::string(pszName))) {
            vIP.push_back(addr);
            return true;
        }
    }

    struct addrinfo aiHint;
    memset(&aiHint, 0, sizeof(struct addrinfo));

    aiHint.ai_socktype = SOCK_STREAM;
    aiHint.ai_protocol = IPPROTO_TCP;
    aiHint.ai_family = AF_UNSPEC;
#ifdef WIN32
    aiHint.ai_flags = fAllowLookup ? 0 : AI_NUMERICHOST;
#else
    aiHint.ai_flags = fAllowLookup ? AI_ADDRCONFIG : AI_NUMERICHOST;
#endif
    struct addrinfo *aiRes = nullptr;
    int nErr = getaddrinfo(pszName, nullptr, &aiHint, &aiRes);
    if (nErr)
        return false;

    struct addrinfo *aiTrav = aiRes;
    while (aiTrav != nullptr && (nMaxSolutions == 0 || vIP.size() < nMaxSolutions))
    {
        CNetAddr resolved;
        if (aiTrav->ai_family == AF_INET)
        {
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in));
            resolved = CNetAddr(((struct sockaddr_in*)(aiTrav->ai_addr))->sin_addr);
        }

        if (aiTrav->ai_family == AF_INET6)
        {
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in6));
            struct sockaddr_in6* s6 = (struct sockaddr_in6*) aiTrav->ai_addr;
            resolved = CNetAddr(s6->sin6_addr, s6->sin6_scope_id);
        }
        /* Never allow resolving to an internal address. Consider any such result invalid */
        if (!resolved.IsInternal()) {
            vIP.push_back(resolved);
        }

        aiTrav = aiTrav->ai_next;
    }

    freeaddrinfo(aiRes);

    return (vIP.size() > 0);
}

bool LookupHost(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
{
    std::string strHost(pszName);
    if (strHost.empty())
        return false;
    if (boost::algorithm::starts_with(strHost, "[") && boost::algorithm::ends_with(strHost, "]"))
    {
        strHost = strHost.substr(1, strHost.size() - 2);
    }

    return LookupIntern(strHost.c_str(), vIP, nMaxSolutions, fAllowLookup);
}

bool LookupHost(const char *pszName, CNetAddr& addr, bool fAllowLookup)
{
    std::vector<CNetAddr> vIP;
    LookupHost(pszName, vIP, 1, fAllowLookup);
    if(vIP.empty())
        return false;
    addr = vIP.front();
    return true;
}

bool Lookup(const char *pszName, std::vector<CService>& vAddr, int portDefault, bool fAllowLookup, unsigned int nMaxSolutions)
{
    if (pszName[0] == 0)
        return false;
    int port = portDefault;
    std::string hostname = "";
    SplitHostPort(std::string(pszName), port, hostname);

    std::vector<CNetAddr> vIP;
    bool fRet = LookupIntern(hostname.c_str(), vIP, nMaxSolutions, fAllowLookup);
    if (!fRet)
        return false;
    vAddr.resize(vIP.size());
    for (unsigned int i = 0; i < vIP.size(); i++)
        vAddr[i] = CService(vIP[i], port);
    return true;
}

bool Lookup(const char *pszName, CService& addr, int portDefault, bool fAllowLookup)
{
    std::vector<CService> vService;
    bool fRet = Lookup(pszName, vService, portDefault, fAllowLookup, 1);
    if (!fRet)
        return false;
    addr = vService[0];
    return true;
}

CService LookupNumeric(const char *pszName, int portDefault)
{
    CService addr;
    // "1.2:345" will fail to resolve the ip, but will still set the port.
    // If the ip fails to resolve, re-init the result.
    if(!Lookup(pszName, addr, portDefault, false))
        addr = CService();
    return addr;
}

struct timeval MillisToTimeval(int64_t nTimeout)
{
    struct timeval timeout;
    timeout.tv_sec  = nTimeout / 1000;
    timeout.tv_usec = (nTimeout % 1000) * 1000;
    return timeout;
}

/** SOCKS version */
enum SOCKSVersion: uint8_t {
    SOCKS4 = 0x04,
    SOCKS5 = 0x05
};

/** Values defined for METHOD in RFC1928 */
enum SOCKS5Method: uint8_t {
    NOAUTH = 0x00,        //! No authentication required
    GSSAPI = 0x01,        //! GSSAPI
    USER_PASS = 0x02,     //! Username/password
    NO_ACCEPTABLE = 0xff, //! No acceptable methods
};

/** Values defined for CMD in RFC1928 */
enum SOCKS5Command: uint8_t {
    CONNECT = 0x01,
    BIND = 0x02,
    UDP_ASSOCIATE = 0x03
};

/** Values defined for REP in RFC1928 */
enum SOCKS5Reply: uint8_t {
    SUCCEEDED = 0x00,        //! Succeeded
    GENFAILURE = 0x01,       //! General failure
    NOTALLOWED = 0x02,       //! Connection not allowed by ruleset
    NETUNREACHABLE = 0x03,   //! Network unreachable
    HOSTUNREACHABLE = 0x04,  //! Network unreachable
    CONNREFUSED = 0x05,      //! Connection refused
    TTLEXPIRED = 0x06,       //! TTL expired
    CMDUNSUPPORTED = 0x07,   //! Command not supported
    ATYPEUNSUPPORTED = 0x08, //! Address type not supported
};

/** Values defined for ATYPE in RFC1928 */
enum SOCKS5Atyp: uint8_t {
    IPV4 = 0x01,
    DOMAINNAME = 0x03,
    IPV6 = 0x04,
};

/** Status codes that can be returned by InterruptibleRecv */
enum class IntrRecvError {
    OK,
    Timeout,
    Disconnected,
    NetworkError,
    Interrupted
};

/**
 * Read bytes from socket. This will either read the full number of bytes requested
 * or return False on error or timeout.
 * This function can be interrupted by calling InterruptSocks5()
 *
 * @param data Buffer to receive into
 * @param len  Length of data to receive
 * @param timeout  Timeout in milliseconds for receive operation
 *
 * @note This function requires that hSocket is in non-blocking mode.
 */
static IntrRecvError InterruptibleRecv(uint8_t* data, size_t len, int timeout, const SOCKET& hSocket)
{
    int64_t curTime = GetTimeMillis();
    int64_t endTime = curTime + timeout;
    // Maximum time to wait in one select call. It will take up until this time (in millis)
    // to break off in case of an interruption.
    const int64_t maxWait = 1000;
    while (len > 0 && curTime < endTime) {
        ssize_t ret = recv(hSocket, (char*)data, len, 0); // Optimistically try the recv first
        if (ret > 0) {
            len -= ret;
            data += ret;
        } else if (ret == 0) { // Unexpected disconnection
            return IntrRecvError::Disconnected;
        } else { // Other error or blocking
            int nErr = WSAGetLastError();
            if (nErr == WSAEINPROGRESS || nErr == WSAEWOULDBLOCK || nErr == WSAEINVAL) {
                if (!IsSelectableSocket(hSocket)) {
<<<<<<< HEAD
                    return IntrRecvError::NetworkError;
=======
                    return false;
>>>>>>> 0.10
                }
                struct timeval tval = MillisToTimeval(std::min(endTime - curTime, maxWait));
                fd_set fdset;
                FD_ZERO(&fdset);
                FD_SET(hSocket, &fdset);
                int nRet = select(hSocket + 1, &fdset, nullptr, nullptr, &tval);
                if (nRet == SOCKET_ERROR) {
                    return IntrRecvError::NetworkError;
                }
            } else {
                return IntrRecvError::NetworkError;
            }
        }
        if (interruptSocks5Recv)
            return IntrRecvError::Interrupted;
        curTime = GetTimeMillis();
    }
    return len == 0 ? IntrRecvError::OK : IntrRecvError::Timeout;
}

/** Credentials for proxy authentication */
struct ProxyCredentials
{
    std::string username;
    std::string password;
};

/** Convert SOCKS5 reply to an error message */
std::string Socks5ErrorString(uint8_t err)
{
    switch(err) {
        case SOCKS5Reply::GENFAILURE:
            return "general failure";
        case SOCKS5Reply::NOTALLOWED:
            return "connection not allowed";
        case SOCKS5Reply::NETUNREACHABLE:
            return "network unreachable";
        case SOCKS5Reply::HOSTUNREACHABLE:
            return "host unreachable";
        case SOCKS5Reply::CONNREFUSED:
            return "connection refused";
        case SOCKS5Reply::TTLEXPIRED:
            return "TTL expired";
        case SOCKS5Reply::CMDUNSUPPORTED:
            return "protocol error";
        case SOCKS5Reply::ATYPEUNSUPPORTED:
            return "address type not supported";
        default:
            return "unknown";
    }
}

/** Connect using SOCKS5 (as described in RFC1928) */
static bool Socks5(const std::string& strDest, int port, const ProxyCredentials *auth, const SOCKET& hSocket)
{
    IntrRecvError recvr;
    LogPrint(BCLog::NET, "SOCKS5 connecting %s\n", strDest);
    if (strDest.size() > 255) {
        return error("Hostname too long");
    }
    // Accepted authentication methods
    std::vector<uint8_t> vSocks5Init;
    vSocks5Init.push_back(SOCKSVersion::SOCKS5);
    if (auth) {
        vSocks5Init.push_back(0x02); // Number of methods
        vSocks5Init.push_back(SOCKS5Method::NOAUTH);
        vSocks5Init.push_back(SOCKS5Method::USER_PASS);
    } else {
        vSocks5Init.push_back(0x01); // Number of methods
        vSocks5Init.push_back(SOCKS5Method::NOAUTH);
    }
    ssize_t ret = send(hSocket, (const char*)vSocks5Init.data(), vSocks5Init.size(), MSG_NOSIGNAL);
    if (ret != (ssize_t)vSocks5Init.size()) {
        return error("Error sending to proxy");
    }
    uint8_t pchRet1[2];
    if ((recvr = InterruptibleRecv(pchRet1, 2, SOCKS5_RECV_TIMEOUT, hSocket)) != IntrRecvError::OK) {
        LogPrintf("Socks5() connect to %s:%d failed: InterruptibleRecv() timeout or other failure\n", strDest, port);
        return false;
    }
    if (pchRet1[0] != SOCKSVersion::SOCKS5) {
        return error("Proxy failed to initialize");
    }
    if (pchRet1[1] == SOCKS5Method::USER_PASS && auth) {
        // Perform username/password authentication (as described in RFC1929)
        std::vector<uint8_t> vAuth;
        vAuth.push_back(0x01); // Current (and only) version of user/pass subnegotiation
        if (auth->username.size() > 255 || auth->password.size() > 255)
            return error("Proxy username or password too long");
        vAuth.push_back(auth->username.size());
        vAuth.insert(vAuth.end(), auth->username.begin(), auth->username.end());
        vAuth.push_back(auth->password.size());
        vAuth.insert(vAuth.end(), auth->password.begin(), auth->password.end());
        ret = send(hSocket, (const char*)vAuth.data(), vAuth.size(), MSG_NOSIGNAL);
        if (ret != (ssize_t)vAuth.size()) {
            return error("Error sending authentication to proxy");
        }
        LogPrint(BCLog::PROXY, "SOCKS5 sending proxy authentication %s:%s\n", auth->username, auth->password);
        uint8_t pchRetA[2];
        if ((recvr = InterruptibleRecv(pchRetA, 2, SOCKS5_RECV_TIMEOUT, hSocket)) != IntrRecvError::OK) {
            return error("Error reading proxy authentication response");
        }
        if (pchRetA[0] != 0x01 || pchRetA[1] != 0x00) {
            return error("Proxy authentication unsuccessful");
        }
    } else if (pchRet1[1] == SOCKS5Method::NOAUTH) {
        // Perform no authentication
    } else {
        return error("Proxy requested wrong authentication method %02x", pchRet1[1]);
    }
    std::vector<uint8_t> vSocks5;
    vSocks5.push_back(SOCKSVersion::SOCKS5); // VER protocol version
    vSocks5.push_back(SOCKS5Command::CONNECT); // CMD CONNECT
    vSocks5.push_back(0x00); // RSV Reserved must be 0
    vSocks5.push_back(SOCKS5Atyp::DOMAINNAME); // ATYP DOMAINNAME
    vSocks5.push_back(strDest.size()); // Length<=255 is checked at beginning of function
    vSocks5.insert(vSocks5.end(), strDest.begin(), strDest.end());
    vSocks5.push_back((port >> 8) & 0xFF);
    vSocks5.push_back((port >> 0) & 0xFF);
    ret = send(hSocket, (const char*)vSocks5.data(), vSocks5.size(), MSG_NOSIGNAL);
    if (ret != (ssize_t)vSocks5.size()) {
        return error("Error sending to proxy");
    }
    uint8_t pchRet2[4];
    if ((recvr = InterruptibleRecv(pchRet2, 4, SOCKS5_RECV_TIMEOUT, hSocket)) != IntrRecvError::OK) {
        if (recvr == IntrRecvError::Timeout) {
            /* If a timeout happens here, this effectively means we timed out while connecting
             * to the remote node. This is very common for Tor, so do not print an
             * error message. */
            return false;
        } else {
            return error("Error while reading proxy response");
        }
    }
    if (pchRet2[0] != SOCKSVersion::SOCKS5) {
        return error("Proxy failed to accept request");
    }
    if (pchRet2[1] != SOCKS5Reply::SUCCEEDED) {
        // Failures to connect to a peer that are not proxy errors
        LogPrintf("Socks5() connect to %s:%d failed: %s\n", strDest, port, Socks5ErrorString(pchRet2[1]));
        return false;
    }
    if (pchRet2[2] != 0x00) { // Reserved field must be 0
        return error("Error: malformed proxy response");
    }
    uint8_t pchRet3[256];
    switch (pchRet2[3])
    {
        case SOCKS5Atyp::IPV4: recvr = InterruptibleRecv(pchRet3, 4, SOCKS5_RECV_TIMEOUT, hSocket); break;
        case SOCKS5Atyp::IPV6: recvr = InterruptibleRecv(pchRet3, 16, SOCKS5_RECV_TIMEOUT, hSocket); break;
        case SOCKS5Atyp::DOMAINNAME:
        {
            recvr = InterruptibleRecv(pchRet3, 1, SOCKS5_RECV_TIMEOUT, hSocket);
            if (recvr != IntrRecvError::OK) {
                return error("Error reading from proxy");
            }
            int nRecv = pchRet3[0];
            recvr = InterruptibleRecv(pchRet3, nRecv, SOCKS5_RECV_TIMEOUT, hSocket);
            break;
        }
        default: return error("Error: malformed proxy response");
    }
    if (recvr != IntrRecvError::OK) {
        return error("Error reading from proxy");
    }
    if ((recvr = InterruptibleRecv(pchRet3, 2, SOCKS5_RECV_TIMEOUT, hSocket)) != IntrRecvError::OK) {
        return error("Error reading from proxy");
    }
    LogPrint(BCLog::NET, "SOCKS5 connected %s\n", strDest);
    return true;
}

SOCKET CreateSocket(const CService &addrConnect)
{
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrConnect.GetSockAddr((struct sockaddr*)&sockaddr, &len)) {
        LogPrintf("Cannot create socket for %s: unsupported network\n", addrConnect.ToString());
        return INVALID_SOCKET;
    }

    SOCKET hSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hSocket == INVALID_SOCKET)
        return INVALID_SOCKET;

    if (!IsSelectableSocket(hSocket)) {
        CloseSocket(hSocket);
        LogPrintf("Cannot create connection: non-selectable socket created (fd >= FD_SETSIZE ?)\n");
        return INVALID_SOCKET;
    }

    int set = 1;
#ifdef SO_NOSIGPIPE
    // Different way of disabling SIGPIPE on BSD
    setsockopt(hSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&set, sizeof(int));
#endif

    //Disable Nagle's algorithm
<<<<<<< HEAD
    SetSocketNoDelay(hSocket);
=======
#ifdef WIN32
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&set, sizeof(int));
#else
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&set, sizeof(int));
#endif
>>>>>>> 0.10

    // Set to non-blocking
    if (!SetSocketNonBlocking(hSocket, true)) {
        CloseSocket(hSocket);
        LogPrintf("ConnectSocketDirectly: Setting socket to non-blocking failed, error %s\n", NetworkErrorString(WSAGetLastError()));
    }
    return hSocket;
}

bool ConnectSocketDirectly(const CService &addrConnect, const SOCKET& hSocket, int nTimeout)
{
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (hSocket == INVALID_SOCKET) {
        LogPrintf("Cannot connect to %s: invalid socket\n", addrConnect.ToString());
        return false;
    }
    if (!addrConnect.GetSockAddr((struct sockaddr*)&sockaddr, &len)) {
        LogPrintf("Cannot connect to %s: unsupported network\n", addrConnect.ToString());
        return false;
    }
    if (connect(hSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        // WSAEINVAL is here because some legacy version of winsock uses it
        if (nErr == WSAEINPROGRESS || nErr == WSAEWOULDBLOCK || nErr == WSAEINVAL)
        {
            struct timeval timeout = MillisToTimeval(nTimeout);
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(hSocket, &fdset);
            int nRet = select(hSocket + 1, nullptr, &fdset, nullptr, &timeout);
            if (nRet == 0)
            {
                LogPrint(BCLog::NET, "connection to %s timeout\n", addrConnect.ToString());
                return false;
            }
            if (nRet == SOCKET_ERROR)
            {
                LogPrintf("select() for %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
                return false;
            }
            socklen_t nRetSize = sizeof(nRet);
#ifdef WIN32
            if (getsockopt(hSocket, SOL_SOCKET, SO_ERROR, (char*)(&nRet), &nRetSize) == SOCKET_ERROR)
#else
            if (getsockopt(hSocket, SOL_SOCKET, SO_ERROR, &nRet, &nRetSize) == SOCKET_ERROR)
#endif
            {
                LogPrintf("getsockopt() for %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
                return false;
            }
            if (nRet != 0)
            {
                LogPrintf("connect() to %s failed after select(): %s\n", addrConnect.ToString(), NetworkErrorString(nRet));
                return false;
            }
        }
#ifdef WIN32
        else if (WSAGetLastError() != WSAEISCONN)
#else
        else
#endif
        {
            LogPrintf("connect() to %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
            return false;
        }
    }
    return true;
}

bool SetProxy(enum Network net, const proxyType &addrProxy) {
    assert(net >= 0 && net < NET_MAX);
    if (!addrProxy.IsValid())
        return false;
    LOCK(cs_proxyInfos);
    proxyInfo[net] = addrProxy;
    return true;
}

bool GetProxy(enum Network net, proxyType &proxyInfoOut) {
    assert(net >= 0 && net < NET_MAX);
    LOCK(cs_proxyInfos);
    if (!proxyInfo[net].IsValid())
        return false;
    proxyInfoOut = proxyInfo[net];
    return true;
}

bool SetNameProxy(const proxyType &addrProxy) {
    if (!addrProxy.IsValid())
        return false;
    LOCK(cs_proxyInfos);
    nameProxy = addrProxy;
    return true;
}

bool GetNameProxy(proxyType &nameProxyOut) {
    LOCK(cs_proxyInfos);
    if(!nameProxy.IsValid())
        return false;
    nameProxyOut = nameProxy;
    return true;
}

bool HaveNameProxy() {
    LOCK(cs_proxyInfos);
    return nameProxy.IsValid();
}

bool IsProxy(const CNetAddr &addr) {
    LOCK(cs_proxyInfos);
    for (int i = 0; i < NET_MAX; i++) {
        if (addr == (CNetAddr)proxyInfo[i].proxy)
            return true;
    }
    return false;
}

bool ConnectThroughProxy(const proxyType &proxy, const std::string& strDest, int port, const SOCKET& hSocket, int nTimeout, bool *outProxyConnectionFailed)
{
    // first connect to proxy server
    if (!ConnectSocketDirectly(proxy.proxy, hSocket, nTimeout)) {
        if (outProxyConnectionFailed)
            *outProxyConnectionFailed = true;
        return false;
    }
    // do socks negotiation
    if (proxy.randomize_credentials) {
        ProxyCredentials random_auth;
        static std::atomic_int counter(0);
        random_auth.username = random_auth.password = strprintf("%i", counter++);
        if (!Socks5(strDest, (unsigned short)port, &random_auth, hSocket)) {
            return false;
<<<<<<< HEAD
=======
    }

    return true;
}

bool CNetAddr::IsRoutable() const
{
    return IsValid() && !(IsRFC1918() || IsRFC2544() || IsRFC3927() || IsRFC4862() || IsRFC6598() || IsRFC5737() || (IsRFC4193() && !IsTor()) || IsRFC4843() || IsLocal());
}

enum Network CNetAddr::GetNetwork() const
{
    if (!IsRoutable())
        return NET_UNROUTABLE;

    if (IsIPv4())
        return NET_IPV4;

    if (IsTor())
        return NET_TOR;

    return NET_IPV6;
}

std::string CNetAddr::ToStringIP() const
{
    if (IsTor())
        return EncodeBase32(&ip[6], 10) + ".onion";
    CService serv(*this, 0);
    struct sockaddr_storage sockaddr;
    socklen_t socklen = sizeof(sockaddr);
    if (serv.GetSockAddr((struct sockaddr*)&sockaddr, &socklen)) {
        char name[1025] = "";
        if (!getnameinfo((const struct sockaddr*)&sockaddr, socklen, name, sizeof(name), NULL, 0, NI_NUMERICHOST))
            return std::string(name);
    }
    if (IsIPv4())
        return strprintf("%u.%u.%u.%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0));
    else
        return strprintf("%x:%x:%x:%x:%x:%x:%x:%x",
                         GetByte(15) << 8 | GetByte(14), GetByte(13) << 8 | GetByte(12),
                         GetByte(11) << 8 | GetByte(10), GetByte(9) << 8 | GetByte(8),
                         GetByte(7) << 8 | GetByte(6), GetByte(5) << 8 | GetByte(4),
                         GetByte(3) << 8 | GetByte(2), GetByte(1) << 8 | GetByte(0));
}

std::string CNetAddr::ToString() const
{
    return ToStringIP();
}

bool operator==(const CNetAddr& a, const CNetAddr& b)
{
    return (memcmp(a.ip, b.ip, 16) == 0);
}

bool operator!=(const CNetAddr& a, const CNetAddr& b)
{
    return (memcmp(a.ip, b.ip, 16) != 0);
}

bool operator<(const CNetAddr& a, const CNetAddr& b)
{
    return (memcmp(a.ip, b.ip, 16) < 0);
}

bool CNetAddr::GetInAddr(struct in_addr* pipv4Addr) const
{
    if (!IsIPv4())
        return false;
    memcpy(pipv4Addr, ip+12, 4);
    return true;
}

bool CNetAddr::GetIn6Addr(struct in6_addr* pipv6Addr) const
{
    memcpy(pipv6Addr, ip, 16);
    return true;
}

// get canonical identifier of an address' group
// no two connections will be attempted to addresses with the same group
std::vector<unsigned char> CNetAddr::GetGroup() const
{
    std::vector<unsigned char> vchRet;
    int nClass = NET_IPV6;
    int nStartByte = 0;
    int nBits = 16;

    // all local addresses belong to the same group
    if (IsLocal())
    {
        nClass = 255;
        nBits = 0;
    }

    // all unroutable addresses belong to the same group
    if (!IsRoutable())
    {
        nClass = NET_UNROUTABLE;
        nBits = 0;
    }
    // for IPv4 addresses, '1' + the 16 higher-order bits of the IP
    // includes mapped IPv4, SIIT translated IPv4, and the well-known prefix
    else if (IsIPv4() || IsRFC6145() || IsRFC6052())
    {
        nClass = NET_IPV4;
        nStartByte = 12;
    }
    // for 6to4 tunnelled addresses, use the encapsulated IPv4 address
    else if (IsRFC3964())
    {
        nClass = NET_IPV4;
        nStartByte = 2;
    }
    // for Teredo-tunnelled IPv6 addresses, use the encapsulated IPv4 address
    else if (IsRFC4380())
    {
        vchRet.push_back(NET_IPV4);
        vchRet.push_back(GetByte(3) ^ 0xFF);
        vchRet.push_back(GetByte(2) ^ 0xFF);
        return vchRet;
    }
    else if (IsTor())
    {
        nClass = NET_TOR;
        nStartByte = 6;
        nBits = 4;
    }
    // for he.net, use /36 groups
    else if (GetByte(15) == 0x20 && GetByte(14) == 0x01 && GetByte(13) == 0x04 && GetByte(12) == 0x70)
        nBits = 36;
    // for the rest of the IPv6 network, use /32 groups
    else
        nBits = 32;

    vchRet.push_back(nClass);
    while (nBits >= 8)
    {
        vchRet.push_back(GetByte(15 - nStartByte));
        nStartByte++;
        nBits -= 8;
    }
    if (nBits > 0)
        vchRet.push_back(GetByte(15 - nStartByte) | ((1 << (8 - nBits)) - 1));

    return vchRet;
}

uint64_t CNetAddr::GetHash() const
{
    uint256 hash = Hash(&ip[0], &ip[16]);
    uint64_t nRet;
    memcpy(&nRet, &hash, sizeof(nRet));
    return nRet;
}

// private extensions to enum Network, only returned by GetExtNetwork,
// and only used in GetReachabilityFrom
static const int NET_UNKNOWN = NET_MAX + 0;
static const int NET_TEREDO  = NET_MAX + 1;
int static GetExtNetwork(const CNetAddr *addr)
{
    if (addr == NULL)
        return NET_UNKNOWN;
    if (addr->IsRFC4380())
        return NET_TEREDO;
    return addr->GetNetwork();
}

/** Calculates a metric for how reachable (*this) is from a given partner */
int CNetAddr::GetReachabilityFrom(const CNetAddr *paddrPartner) const
{
    enum Reachability {
        REACH_UNREACHABLE,
        REACH_DEFAULT,
        REACH_TEREDO,
        REACH_IPV6_WEAK,
        REACH_IPV4,
        REACH_IPV6_STRONG,
        REACH_PRIVATE
    };

    if (!IsRoutable())
        return REACH_UNREACHABLE;

    int ourNet = GetExtNetwork(this);
    int theirNet = GetExtNetwork(paddrPartner);
    bool fTunnel = IsRFC3964() || IsRFC6052() || IsRFC6145();

    switch(theirNet) {
    case NET_IPV4:
        switch(ourNet) {
        default:       return REACH_DEFAULT;
        case NET_IPV4: return REACH_IPV4;
        }
    case NET_IPV6:
        switch(ourNet) {
        default:         return REACH_DEFAULT;
        case NET_TEREDO: return REACH_TEREDO;
        case NET_IPV4:   return REACH_IPV4;
        case NET_IPV6:   return fTunnel ? REACH_IPV6_WEAK : REACH_IPV6_STRONG; // only prefer giving our IPv6 address if it's not tunnelled
        }
    case NET_TOR:
        switch(ourNet) {
        default:         return REACH_DEFAULT;
        case NET_IPV4:   return REACH_IPV4; // Tor users can connect to IPv4 as well
        case NET_TOR:    return REACH_PRIVATE;
>>>>>>> 0.10
        }
    } else {
        if (!Socks5(strDest, (unsigned short)port, 0, hSocket)) {
            return false;
        }
    }
    return true;
}
bool LookupSubNet(const char* pszName, CSubNet& ret)
{
    std::string strSubnet(pszName);
    size_t slash = strSubnet.find_last_of('/');
    std::vector<CNetAddr> vIP;

    std::string strAddress = strSubnet.substr(0, slash);
    if (LookupHost(strAddress.c_str(), vIP, 1, false))
    {
        CNetAddr network = vIP[0];
        if (slash != strSubnet.npos)
        {
            std::string strNetmask = strSubnet.substr(slash + 1);
            int32_t n;
            // IPv4 addresses start at offset 12, and first 12 bytes must match, so just offset n
<<<<<<< HEAD
            if (ParseInt32(strNetmask, &n)) { // If valid number, assume /24 syntax
                ret = CSubNet(network, n);
                return ret.IsValid();
            }
            else // If not a valid number, try full netmask syntax
            {
                // Never allow lookup for netmask
                if (LookupHost(strNetmask.c_str(), vIP, 1, false)) {
                    ret = CSubNet(network, vIP[0]);
                    return ret.IsValid();
=======
            const int astartofs = network.IsIPv4() ? 12 : 0;
            if (ParseInt32(strNetmask, &n)) // If valid number, assume /24 symtex
            {
                if(n >= 0 && n <= (128 - astartofs*8)) // Only valid if in range of bits of address
                {
                    n += astartofs*8;
                    // Clear bits [n..127]
                    for (; n < 128; ++n)
                        netmask[n>>3] &= ~(1<<(7-(n&7)));
                }
                else
                {
                    valid = false;
                }
            }
            else // If not a valid number, try full netmask syntax
            {
                if (LookupHost(strNetmask.c_str(), vIP, 1, false)) // Never allow lookup for netmask
                {
                    // Copy only the *last* four bytes in case of IPv4, the rest of the mask should stay 1's as
                    // we don't want pchIPv4 to be part of the mask.
                    for(int x=astartofs; x<16; ++x)
                        netmask[x] = vIP[0].ip[x];
                }
                else
                {
                    valid = false;
>>>>>>> 0.10
                }
            }
        }
        else
        {
            ret = CSubNet(network);
            return ret.IsValid();
        }
    }
<<<<<<< HEAD
    return false;
=======
    else
    {
        valid = false;
    }

    // Normalize network according to netmask
    for(int x=0; x<16; ++x)
        network.ip[x] &= netmask[x];
}

bool CSubNet::Match(const CNetAddr &addr) const
{
    if (!valid || !addr.IsValid())
        return false;
    for(int x=0; x<16; ++x)
        if ((addr.ip[x] & netmask[x]) != network.ip[x])
            return false;
    return true;
}

std::string CSubNet::ToString() const
{
    std::string strNetmask;
    if (network.IsIPv4())
        strNetmask = strprintf("%u.%u.%u.%u", netmask[12], netmask[13], netmask[14], netmask[15]);
    else
        strNetmask = strprintf("%x:%x:%x:%x:%x:%x:%x:%x",
                         netmask[0] << 8 | netmask[1], netmask[2] << 8 | netmask[3],
                         netmask[4] << 8 | netmask[5], netmask[6] << 8 | netmask[7],
                         netmask[8] << 8 | netmask[9], netmask[10] << 8 | netmask[11],
                         netmask[12] << 8 | netmask[13], netmask[14] << 8 | netmask[15]);
    return network.ToString() + "/" + strNetmask;
}

bool CSubNet::IsValid() const
{
    return valid;
}

bool operator==(const CSubNet& a, const CSubNet& b)
{
    return a.valid == b.valid && a.network == b.network && !memcmp(a.netmask, b.netmask, 16);
}

bool operator!=(const CSubNet& a, const CSubNet& b)
{
    return !(a==b);
>>>>>>> 0.10
}

#ifdef WIN32
std::string NetworkErrorString(int err)
{
    char buf[256];
    buf[0] = 0;
    if(FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            buf, sizeof(buf), nullptr))
    {
        return strprintf("%s (%d)", buf, err);
    }
    else
    {
        return strprintf("Unknown error (%d)", err);
    }
}
#else
std::string NetworkErrorString(int err)
{
    char buf[256];
    buf[0] = 0;
    /* Too bad there are two incompatible implementations of the
     * thread-safe strerror. */
    const char *s;
#ifdef STRERROR_R_CHAR_P /* GNU variant can return a pointer outside the passed buffer */
    s = strerror_r(err, buf, sizeof(buf));
#else /* POSIX variant always returns message in buffer */
    s = buf;
    if (strerror_r(err, buf, sizeof(buf)))
        buf[0] = 0;
#endif
    return strprintf("%s (%d)", s, err);
}
#endif

bool CloseSocket(SOCKET& hSocket)
{
    if (hSocket == INVALID_SOCKET)
        return false;
#ifdef WIN32
    int ret = closesocket(hSocket);
#else
    int ret = close(hSocket);
#endif
    if (ret) {
        LogPrintf("Socket close failed: %d. Error: %s\n", hSocket, NetworkErrorString(WSAGetLastError()));
    }
    hSocket = INVALID_SOCKET;
    return ret != SOCKET_ERROR;
}

bool SetSocketNonBlocking(const SOCKET& hSocket, bool fNonBlocking)
{
    if (fNonBlocking) {
#ifdef WIN32
        u_long nOne = 1;
        if (ioctlsocket(hSocket, FIONBIO, &nOne) == SOCKET_ERROR) {
#else
        int fFlags = fcntl(hSocket, F_GETFL, 0);
        if (fcntl(hSocket, F_SETFL, fFlags | O_NONBLOCK) == SOCKET_ERROR) {
#endif
            return false;
        }
    } else {
#ifdef WIN32
        u_long nZero = 0;
        if (ioctlsocket(hSocket, FIONBIO, &nZero) == SOCKET_ERROR) {
#else
        int fFlags = fcntl(hSocket, F_GETFL, 0);
        if (fcntl(hSocket, F_SETFL, fFlags & ~O_NONBLOCK) == SOCKET_ERROR) {
#endif
            return false;
        }
    }

    return true;
}

bool SetSocketNoDelay(const SOCKET& hSocket)
{
    int set = 1;
    int rc = setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&set, sizeof(int));
    return rc == 0;
}

void InterruptSocks5(bool interrupt)
{
    interruptSocks5Recv = interrupt;
}
