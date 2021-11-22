import java.util.ArrayList;

public class IPLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

    _IP_HEADER m_sHeader;
    
    public static ArrayList<_ROUTING_ELEMENT> Routing_Table = new ArrayList<_ROUTING_ELEMENT>();
    
    public class _ROUTING_ELEMENT {
    	byte[] dstAddress;
        byte[] subnet;
        byte[] gateway;
    	String flag;
    	int adaptNum;
    	
    	public _ROUTING_ELEMENT(byte[] dst, byte[] subnet, byte[] gateway, String flag, int adaptNum) {
    		this.dstAddress = dst;
    		this.subnet = subnet;
    		this.gateway = gateway;
    		this.flag = flag;
    		this.adaptNum = adaptNum;
    	}
    }

    public void addRoutingEntry(byte[] dst, byte[] subnet, byte[] gateway, String flag, int adaptNum) {
        _ROUTING_ELEMENT newItem = new _ROUTING_ELEMENT(dst, subnet, gateway, flag, adaptNum);
        Routing_Table.add(newItem);

        ARPDlg.UpdateRoutingTableWindow(Routing_Table);
    }

    public void deleteRoutingEntry(int idx) {
        Routing_Table.remove(idx);

        ARPDlg.UpdateRoutingTableWindow(Routing_Table);
    }
    
    private class _IP_HEADER {
        byte ip_verlen;     // ip version->IPv4 : 4 (1 byte)
        byte ip_tos;        // type of service
        byte[] ip_len;      // total packet length
        byte[] ip_id;       // datagram id
        byte[] ip_fragoff;  // fragment offset
        byte ip_ttl;        // time to live in gateway hops
        byte ip_proto;      // IP protocol
        byte[] ip_cksum;    // header checksum
        _IP_ADDR ip_src;    // source IP address
        _IP_ADDR ip_dst;    // destination IP address

        public _IP_HEADER() {				// 20 Bytes
            this.ip_verlen = (byte) 0x00;       // 1 Byte / 0
            this.ip_tos = (byte) 0x00;          // 1 Byte / 1
            this.ip_len = new byte[2];          // 2 Byte / 2 ~ 3
            this.ip_id = new byte[2];           // 2 Byte / 4 ~ 5
            this.ip_fragoff = new byte[2];      // 2 Byte / 6 ~ 7
            this.ip_ttl = (byte) 0x00;          // 1 Byte / 8
            this.ip_proto = (byte) 0x00;        // 1 Byte / 9
            this.ip_cksum = new byte[2];        // 2 Byte / 10 ~ 11
            this.ip_src = new _IP_ADDR();       // 4 Byte / 12 ~ 15
            this.ip_dst = new _IP_ADDR();       // 4 Byte / 16 ~ 19
        }
    }

    private void ResetHeader(){
        m_sHeader = new _IP_HEADER();
    }

    public IPLayer(String pName){
        pLayerName = pName;
        ResetHeader();
    }

    private class _IP_ADDR {
        byte[] addr = new byte[4];

        public _IP_ADDR() {
            this.addr[0] = (byte) 0x00;
            this.addr[1] = (byte) 0x00;
            this.addr[2] = (byte) 0x00;
            this.addr[3] = (byte) 0x00;
        }
        public _IP_ADDR(byte[] addr) {
            this.addr[0] = addr[0];
            this.addr[1] = addr[1];
            this.addr[2] = addr[2];
            this.addr[3] = addr[3];
        }
    }

    public byte[] objToByte(_IP_HEADER Header, byte[] input, int length) {//data�� ��� �ٿ��ֱ�
        byte[] buf = new byte[length + 20];

        buf[0] = Header.ip_verlen;
        buf[1] = Header.ip_tos;
        buf[2] = Header.ip_len[0];
        buf[3] = Header.ip_len[1];
        buf[4] = Header.ip_id[0];
        buf[5] = Header.ip_id[1];
        buf[6] = Header.ip_fragoff[0];
        buf[7] = Header.ip_fragoff[1];
        buf[8] = Header.ip_ttl;
        buf[9] = Header.ip_proto;
        buf[10] = Header.ip_cksum[0];
        buf[11] = Header.ip_cksum[1];
        for(int i = 0; i < 4; i++) {
            buf[12+i] =Header.ip_src.addr[i];
        }
        for(int i = 0; i < 4; i++) {
            buf[16+i] =Header.ip_dst.addr[i];
        }

        if (length >= 0) System.arraycopy(input, 0, buf, 20, length);

        return buf;
    }

    public boolean chkIfMyIP(byte[] ip) {
        for(int i = 0; i < 4; i++) {
            if(m_sHeader.ip_src.addr[i] != ip[i])
                return false;
        }
        return true;
    }
    
    public byte[] calcMask(byte[] dstIp, byte[] mask) {
    	/*
    	 * 목적지 IP주소와 subnet mask의 bit AND 결과를 리턴 
    	 */
    	byte[] result = new byte[4];
    	
    	for(int i = 0; i < 4; i++) {
    		result[i] = (byte) (dstIp[i] & mask[i]);
    	}
    	
    	return result;
    }
    
    public boolean compareIp(byte[] ip1, byte[] ip2) {
    	/*
    	 * 두 IP를 비교하여 같으면 true, 다르면 false를 리턴
    	 */
    	for(int i = 0; i < 4; i++) {
    		if(ip1[i] != ip2[i]) {
    			return false;
    		}
    	}
    	return true;
    }
    
    public int selectPort(byte[] dstIp) {
    	/*
    	 * Routing Table을 조회하여 보내야 할 port number를 리턴
    	 */
    	for(int i = 0; i < Routing_Table.size(); i++) {
    		byte[] mask_result = this.calcMask(dstIp, Routing_Table.get(i).subnet);
    		if(compareIp(Routing_Table.get(i).dstAddress, mask_result)) {
    			return Routing_Table.get(i).adaptNum;
    		}
    	}
    	return -1;
    }

    public boolean Send(byte[] input, int length, String dstIP) {
        // Header ip_dst Setting
        byte[] dstIP_bytearr = new byte[4];
        String[] byte_ip = dstIP.split("\\.");
        for (int i = 0; i < 4; i++) {
            dstIP_bytearr[i] = (byte) Integer.parseInt(byte_ip[i], 10);
        }
        this.m_sHeader.ip_dst.addr = dstIP_bytearr;

        if(chkIfMyIP(dstIP_bytearr)){
            // 내 IP이면 아무것도 안함
            // ARP Send에서 dstIP가 자기자신이면 보내지 않아야 하므로
            // GARP는 따로 GARPSend() 함수를 만드는게 좋을 것 같아요
            return true;
        }

        // Send
        byte[] bytes;
        m_sHeader.ip_len = intToByte2(length);
        m_sHeader.ip_id[0] = (byte) 0x00;
        m_sHeader.ip_id[1] = (byte) 0x00;
        m_sHeader.ip_fragoff[0] = (byte) 0x00;
        m_sHeader.ip_fragoff[1] = (byte) 0x00;
        m_sHeader.ip_cksum[0] = (byte) 0x00;
        m_sHeader.ip_cksum[1] = (byte) 0x00;

        bytes = objToByte(m_sHeader, input, input.length);
        this.GetUnderLayer().GetUpperLayer(0).Send(bytes, bytes.length, dstIP); // to ARP Layer

        return true;
    }

    public boolean Send(byte[] input, int length, int portNum) {

        this.GetUnderLayer().Send(input, length, portNum); // to EthernetLayer

        return true;
    }
    //ARPLayer의 G-ARP Send 함수 호출.
    public boolean GARP_Send(){
        ((ARPLayer)((EthernetLayer)this.GetUnderLayer()).GetUpperLayer(0)).GARP_Send();
        return true;
    }

    public byte[] RemoveIPHeader(byte[] input, int length) {
        byte[] cpyInput = new byte[length - 20];
        System.arraycopy(input, 20, cpyInput, 0, length - 20);
        input = cpyInput;
        return input;
    }

    public synchronized boolean Receive(byte[] input) {

        byte[] dstIP = new byte[4];
        System.arraycopy(input,16,dstIP,0,4);
        int portNum = selectPort(dstIP);

        Send(input, input.length, portNum);
        return true;
    }

    private byte[] intToByte2(int value) {
        byte[] temp = new byte[2];
        temp[0] |= (byte) ((value & 0xFF00) >> 8);
        temp[1] |= (byte) (value & 0xFF);

        return temp;
    }

    private int byte2ToInt(byte value1, byte value2) {
        return (int)((value1 << 8) | (value2));
    }

    public void SetSrcIPAddress(byte[] srcAddress) {
        m_sHeader.ip_src.addr = srcAddress;
    }

    @Override
    public String GetLayerName() {
        return pLayerName;
    }

    @Override
    public BaseLayer GetUnderLayer() {
        if (p_UnderLayer == null)
            return null;
        return p_UnderLayer;
    }

    @Override
    public BaseLayer GetUpperLayer(int nindex) {
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        if (pUnderLayer == null)
            return;
        this.p_UnderLayer = pUnderLayer;
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);
    }
}
