package function;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import jpcap.packet.*;


public class PacketAnalyze {
    static Packet packet;
    static HashMap<String,String> flag,flag1;
    public PacketAnalyze(Packet packet){
        this.packet = packet;
    }
    //其他类所用方法
    public static HashMap<String,String> packetClass() {
        flag1 = new HashMap<String, String>();
        if(packet.getClass().equals(ARPPacket.class))
        {flag1=ARPanalyze();return flag;}
        else if(packet.getClass().equals(IPPacket.class)&&!packet.getClass().equals(TCPPacket.class)&&!packet.getClass().equals(UDPPacket.class)){
            flag1=ICMPv6analyze();return flag;
        } //将非TCP和UDP的IP包暂时识别为ICMPv6包，做下一步处理
        else {
            if (packet.getClass().equals(ICMPPacket.class)) {
                flag1 = ICMPanalyze();
            } else if (packet.getClass().equals(TCPPacket.class)) {
                flag1 = TCPanalyze();
            } else if (packet.getClass().equals(UDPPacket.class)) {
                flag1 = UDPanalyze();
            }
            return flag;
        }

    } //判断包的类别
    public static HashMap<String,String> IPanalyze(){
        flag = new HashMap<String,String>();
        if(packet instanceof IPPacket){
            IPPacket ippacket = (IPPacket) packet;
            flag.put("协议", "IPv"+String.valueOf(ippacket.version));
            flag.put("源IP", String.valueOf(ippacket.src_ip).substring(1));
            flag.put("目的IP", String.valueOf(ippacket.dst_ip).substring(1));
            flag.put("TTL", String.valueOf(ippacket.hop_limit));
            flag.put("头长度", String.valueOf(ippacket.header.length));
            flag.put("协议号",String.valueOf(ippacket.protocol));
            if(ippacket.version==4)
                flag.put("是否有其他切片", String.valueOf(ippacket.more_frag));
        }
        return flag;
    } //IP包分析
    public static HashMap<String,String> ARPanalyze(){
        flag = new HashMap<String,String>();
        if(packet instanceof ARPPacket){
            ARPPacket ippacket = (ARPPacket) packet;
            flag.put("协议", new String("ARP"));
            flag.put("源IP",String.valueOf(ippacket.getSenderProtocolAddress()).substring(1));
            flag.put("目的IP", String.valueOf(ippacket.getTargetProtocolAddress()).substring(1));
            flag.put("发送方硬件地址",String.valueOf(ippacket.getSenderHardwareAddress()));
            flag.put("目的方硬件地址",String.valueOf(ippacket.getTargetHardwareAddress()));
        }
        return flag;
    } //ARP包分析
    public static HashMap<String,String> ICMPanalyze(){
        flag = new HashMap<String,String>();
        ICMPPacket icmppacket = (ICMPPacket) packet;
        flag.put("协议", new String("ICMP"));
        flag.put("源IP", String.valueOf(icmppacket.src_ip).substring(1));
        flag.put("目的IP", String.valueOf(icmppacket.dst_ip).substring(1));
        return flag;
    }   //ICMP包分析
    public static HashMap<String,String> ICMPv6analyze(){
        flag = new HashMap<String,String>();
        if(packet instanceof IPPacket){
            IPPacket ippacket = (IPPacket) packet;
            if(ippacket.version==6 && ippacket.protocol==58){      //ICMPv6的协议号为58
                flag.put("协议", "ICMPv6");
                flag.put("源IP", String.valueOf(ippacket.src_ip).substring(1));
                flag.put("目的IP", String.valueOf(ippacket.dst_ip).substring(1));
            }


        }
        return flag;
    }
    // jpcap无法分析icmpv6协议，会将其归类到ip协议中。
    public static HashMap<String,String> TCPanalyze(){
        flag = new HashMap<String,String>();
        TCPPacket tcppacket = (TCPPacket) packet;
        EthernetPacket ethernetPacket=(EthernetPacket)packet.datalink;
        if((tcppacket.dst_port==80||tcppacket.src_port==80))
            if(new String(tcppacket.data).contains("HTTP"))
                flag.put("协议", new String("HTTP")); //使用80端口,且数据里含有HTTP字段的TCP是HTTP协议
            else
                flag.put("协议", new String("TCP"));

        else
            flag.put("协议", new String("TCP"));
        flag.put("源IP", String.valueOf(tcppacket.src_ip).substring(1));
        flag.put("源端口", String.valueOf(tcppacket.src_port));
        flag.put("目的IP", String.valueOf(tcppacket.dst_ip).substring(1));
        flag.put("目的端口", String.valueOf(tcppacket.dst_port));
        flag.put("源MAC", ethernetPacket.getSourceAddress());
        flag.put("目的MAC", ethernetPacket.getDestinationAddress());
        flag.put("seq序号",String.valueOf(tcppacket.sequence));
        flag.put("ACK标志",String.valueOf(tcppacket.ack));
        try {
            flag.put("数据", new String(tcppacket.data,"gb18030"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return flag;
    }   //TCP包分析
    public static HashMap<String,String> UDPanalyze(){
        flag = new HashMap<String,String>();
        UDPPacket udppacket = (UDPPacket) packet;
        EthernetPacket ethernetPacket=(EthernetPacket)packet.datalink;
        flag.put("协议", new String("UDP"));
        flag.put("源IP", String.valueOf(udppacket.src_ip).substring(1));
        flag.put("源端口", String.valueOf(udppacket.src_port));
        flag.put("目的IP", String.valueOf(udppacket.dst_ip).substring(1));
        flag.put("目的端口", String.valueOf(udppacket.dst_port));
        flag.put("源MAC", ethernetPacket.getSourceAddress());
        flag.put("目的MAC", ethernetPacket.getDestinationAddress());
        try {
            flag.put("数据", new String(udppacket.data,"gb18030"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return flag;
    }  //UDP包分析
}
