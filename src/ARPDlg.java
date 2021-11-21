import org.jnetpcap.PcapIf;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Map;

public class ARPDlg extends JFrame implements BaseLayer {
	
	public class AddressTableEntry {
		byte[] srcIpAddr;
		byte[] srcMacAddr;
		
		public AddressTableEntry(byte[] srcIp, byte[] srcMac) {
			// TODO Auto-generated constructor stub
			this.srcIpAddr = srcIp;
			this.srcMacAddr = srcMac;
		}
	}

	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	BaseLayer UnderLayer;
	public static ArrayList<AddressTableEntry> AddressTable = new ArrayList<AddressTableEntry>();

	private static LayerManager m_LayerMgr = new LayerManager();
	
	Container contentPane;
	
	// ARP Cache
	JTextArea ARPCacheTableArea;
	JList list_arp_cache;		// arp cache list
	static DefaultListModel model_arp;	// 실제 arp cache 데이터
	JScrollPane scroll_arp;		// 스크롤 속성(arp)
	JButton Item_Delete_Button;	// Item Delete 버튼
	JButton All_Delete_Button;	// All Delete 버튼
	private JTextField targetIPWrite;

	// Routing Table
	JList list_routing;			// routing table list
	static DefaultListModel model_routing;	// 실제 routing table entry 데이터
	JScrollPane scroll_routing;		// 스크롤 속성
	JButton Add_Button_Routing;		// Add 버튼
	JButton Delete_Button_Routing;	// Delete 버튼
	JDialog addDialog;			// add routing entry 다이얼로그

	// Source Address Setting
	JButton Setting_Button;		// Source MAC, IP 세팅 버튼
	JButton ARP_send_Button;	// ARP 패킷 전송 버튼
	static JComboBox<String> NICComboBox;	// 랜카드 선택 ComboBox
	static JComboBox<String> NICComboBox2;	// 랜카드 선택 ComboBox2

	// 임시 변수
	byte[] srcMacAddr1;
	byte[] srcIpAddr1;
	byte[] srcMacAddr2;
	byte[] srcIpAddr2;
	// 임시 변수

	int adapterNumber = 0;
	int adapterNumber2 = 0;

	public static void main(String[] args) {

		// 모든 레이어 추가 및 연결
		// 하위 계층의 순서를 정함
		m_LayerMgr.AddLayer(new NILayer("NI"));
		m_LayerMgr.AddLayer(new EthernetLayer("Ethernet"));
		m_LayerMgr.AddLayer(new ARPLayer("ARP"));
		m_LayerMgr.AddLayer(new IPLayer("IP"));
		m_LayerMgr.AddLayer(new ApplicationLayer("Application"));
		m_LayerMgr.AddLayer(new ARPDlg("GUI"));
		
		m_LayerMgr.ConnectLayers(" NI ( *Ethernet ( *ARP ( *IP ) *IP ( *Application ( *GUI ) ) ) )");
	}

	public ARPDlg(String pName) {
		pLayerName = pName;

		// Frame
		setTitle("Static Router");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(250, 250, 900, 580);
		contentPane = new JPanel();
		((JComponent) contentPane).setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		// ARP Cache Table GUI - START
		// ARP Cache Table panel
		JPanel arpPanel = new JPanel();
		arpPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "ARP Cache",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		arpPanel.setBounds(10, 5, 360, 310);
		contentPane.add(arpPanel);
		arpPanel.setLayout(null);

		// Cache Table Items panel
		JPanel arpCacheTablePanel = new JPanel();
		arpCacheTablePanel.setBounds(10, 15, 340, 210);
		arpPanel.add(arpCacheTablePanel);
		arpCacheTablePanel.setLayout(null);

		// Cache Table Items List
		model_arp = new DefaultListModel();
		list_arp_cache = new JList(model_arp);
		list_arp_cache.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);	// 하나만 선택가능하도록
		scroll_arp = new JScrollPane(list_arp_cache);	// make scrollable
		scroll_arp.setBorder(BorderFactory.createEmptyBorder(0,5,5,5));
		scroll_arp.setBounds(0, 0, 340, 210);
		arpCacheTablePanel.add(scroll_arp);

		// ARP Cache Item Manage Buttons panel
		JPanel arpCacheManageButtonPanel = new JPanel();
		arpCacheManageButtonPanel.setBounds(10, 230, 340, 30);
		arpPanel.add(arpCacheManageButtonPanel);
		arpCacheManageButtonPanel.setLayout(null);

		// Item Delete Button - arp cache
		Item_Delete_Button = new JButton("Item Delete");
		Item_Delete_Button.setBounds(70, 2, 100, 25);
		Item_Delete_Button.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if(e.getSource() == Item_Delete_Button) {
					int selected_index = list_arp_cache.getSelectedIndex();
					if(selected_index < 0) {	// 선택된 항목이 없는 경우 예외처리
						if(model_arp.size() == 0) return;	// 아무것도 없는경우
						selected_index = 0;
					}
					String item = model_arp.getElementAt(selected_index).toString();
					ARPLayer.deleteARPEntry(item.substring(0,19).trim());	// IP주소만 잘라서 key로 전달
				}
			}
		});

		arpCacheManageButtonPanel.add(Item_Delete_Button);

		// All Delete Button - arp cache
		All_Delete_Button = new JButton("All Delete");
		All_Delete_Button.setBounds(180, 2, 100, 25);
		All_Delete_Button.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if(e.getSource() == All_Delete_Button) {
					// TODO: 전체 항목 삭제 - DONE
					ARPLayer.deleteAllARPEntry();
				}
			}
		});
		arpCacheManageButtonPanel.add(All_Delete_Button);

		/*
		// target IP address input panel
		JPanel targetIPaddrInputPanel = new JPanel();
		targetIPaddrInputPanel.setBounds(10, 270, 340, 30);
		arpPanel.add(targetIPaddrInputPanel);
		targetIPaddrInputPanel.setLayout(null);

		// target IP address input label
		JLabel targetIPLabel = new JLabel("IP 주소");
		targetIPLabel.setBounds(0, 0, 50, 20);
		targetIPaddrInputPanel.add(targetIPLabel);

		// target IP address input textfield
		targetIPWrite = new JTextField();
		targetIPWrite.setBounds(50, 2, 200, 20);// 249
		targetIPaddrInputPanel.add(targetIPWrite);
		targetIPWrite.setColumns(10);

		// ARP Test Send Button
		ARP_send_Button = new JButton("Send");
		ARP_send_Button.setBounds(255, 2, 80, 20);
		ARP_send_Button.addActionListener(new sendButtonListener());
		targetIPaddrInputPanel.add(ARP_send_Button);
		*/
		// ARP Cache GUI - END

		// Source Address Setting GUI - START
		// Source Address Setting panel
		JPanel srcAddrSettingPanel = new JPanel();// file panel
		srcAddrSettingPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Src Address Setting",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		srcAddrSettingPanel.setBounds(10, 330, 360, 190);
		contentPane.add(srcAddrSettingPanel);
		srcAddrSettingPanel.setLayout(null);

		JLabel NICLabel = new JLabel("NIC List");
		NICLabel.setBounds(10, 20, 170, 20);
		srcAddrSettingPanel.add(NICLabel);

		// NIC Combo Box
		NICComboBox = new JComboBox();
		NICComboBox.setBounds(10, 50, 170, 20);
		srcAddrSettingPanel.add(NICComboBox);

		NICComboBox2 = new JComboBox();
		NICComboBox2.setBounds(10, 80, 170, 20);
		srcAddrSettingPanel.add(NICComboBox2);

//		lblsrcMAC = new JLabel("Source Mac Address");
//		lblsrcMAC.setBounds(10, 80, 170, 20); //�쐞移� 吏��젙
//		srcAddrSettingPanel.add(lblsrcMAC); //panel 異붽�
//
//		srcMacAddress = new JTextArea();
//		srcMacAddress.setBounds(10, 105, 170, 20);
//		srcMacAddress.setBorder(BorderFactory.createLineBorder(Color.black));
//		srcAddrSettingPanel.add(srcMacAddress);// src address

		Setting_Button = new JButton("Setting");// setting
		Setting_Button.setBounds(200, 80, 130, 20);
		Setting_Button.addActionListener(new setAddressListener());
		srcAddrSettingPanel.add(Setting_Button);// setting

		// NILayer로부터 랜카드 정보 가져오기
		NILayer tempNiLayer = (NILayer) m_LayerMgr.GetLayer("NI");

		for (int i = 0; i < tempNiLayer.getAdapterList().size(); i++) {
			PcapIf pcapIf = tempNiLayer.GetAdapterObject(i); //
			NICComboBox.addItem(pcapIf.getName());
		}

		for (int i = 0; i < tempNiLayer.getAdapterList().size(); i++) {
			PcapIf pcapIf = tempNiLayer.GetAdapterObject(i); //
			NICComboBox2.addItem(pcapIf.getName());
		}

		NICComboBox.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				// adapterNumber = NICComboBox.getSelectedIndex();
				JComboBox jcombo = (JComboBox) e.getSource();
				adapterNumber = jcombo.getSelectedIndex();
				System.out.println("Index: " + adapterNumber);
				try {
					byte[] srcMacAddr = ((NILayer) m_LayerMgr.GetLayer("NI"))
							.GetAdapterObject(adapterNumber).getHardwareAddress();
					byte[] srcIpAddr = ((NILayer) m_LayerMgr.GetLayer("NI"))
							.GetAdapterObject(adapterNumber).getAddresses().get(0).getAddr().getData();
					get_MacAddress(srcMacAddr);	// print 용도
					get_IpAddress(srcIpAddr);	// print 용도

					srcMacAddr1 = srcMacAddr;
					srcIpAddr1 = srcIpAddr;

				} catch (IOException e1) {
					e1.printStackTrace();
				}
			}
		});


		NICComboBox2.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				// adapterNumber = NICComboBox.getSelectedIndex();
				JComboBox jcombo = (JComboBox) e.getSource();
				adapterNumber2 = jcombo.getSelectedIndex();
				System.out.println("Index: " + adapterNumber2);
				try {
					byte[] srcMacAddr = ((NILayer) m_LayerMgr.GetLayer("NI"))
							.GetAdapterObject(adapterNumber2).getHardwareAddress();
					byte[] srcIpAddr = ((NILayer) m_LayerMgr.GetLayer("NI"))
							.GetAdapterObject(adapterNumber2).getAddresses().get(0).getAddr().getData();
					get_MacAddress(srcMacAddr);	// print 용도
					get_IpAddress(srcIpAddr);	// print 용도

					srcMacAddr2 = srcMacAddr;
					srcIpAddr2 = srcIpAddr;

				} catch (IOException e1) {
					e1.printStackTrace();
				}
			}
		});

//		try {
//			srcMacAddress.append(get_MacAddress(
//					((NILayer) m_LayerMgr.GetLayer("NI")).GetAdapterObject(adapterNumber).getHardwareAddress()));
//		} catch (IOException e1) {
//			e1.printStackTrace();
//		};

		// Source Address Setting GUI - END

		// Routing Table Entry GUI - START
		// Routing Table Entry panel
		JPanel routingPanel = new JPanel();
		routingPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Routing Table Entry",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		routingPanel.setBounds(380, 5, 470, 280);
		contentPane.add(routingPanel);
		routingPanel.setLayout(null);

		// Routing Table panel
		JPanel routingTablePanel = new JPanel();
		routingTablePanel.setBounds(10, 15, 450, 210);
		routingPanel.add(routingTablePanel);
		routingTablePanel.setLayout(null);

		// Routing Entry Table Items List
		model_routing = new DefaultListModel();
		list_routing = new JList(model_routing);
		list_routing.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);	// 하나만 선택가능하도록
		scroll_routing = new JScrollPane(list_routing);	// make scrollable
		scroll_routing.setBorder(BorderFactory.createEmptyBorder(0,5,5,5));
		scroll_routing.setBounds(0, 0, 470, 210);
		routingTablePanel.add(scroll_routing);

		// Routing Entry Item Manage Buttons panel
		JPanel routingManageButtonPanel = new JPanel();
		routingManageButtonPanel.setBounds(10, 230, 340, 30);
		routingPanel.add(routingManageButtonPanel);
		routingManageButtonPanel.setLayout(null);

		// Add Button - routing
		Add_Button_Routing = new JButton("Add");
		Add_Button_Routing.setBounds(70, 2, 100, 25);
		addDialog = new AddProxyDialog(this, "Routing Table Entry 추가");	// 추가 dialog
		Add_Button_Routing.addActionListener(new ActionListener () {
			// Routing Table Entry 추가 다이얼로그 띄우기
			@Override
			public void actionPerformed(ActionEvent e) {
				if (e.getSource() == Add_Button_Routing) {
					addDialog.setVisible(true);
				}
			}
		});
		routingManageButtonPanel.add(Add_Button_Routing);

		// Delete Button - routing
		Delete_Button_Routing = new JButton("Delete");
		Delete_Button_Routing.setBounds(180, 2, 100, 25);
		Delete_Button_Routing.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO: Delete 버튼 클릭 이벤트 처리 - DONE
				if(e.getSource() == Delete_Button_Routing) {
					int selected_index = list_routing.getSelectedIndex();
					if(selected_index < 0) {	// 선택된 항목이 없는 경우 예외처리
						if(model_routing.size() == 0) return;	// 아무것도 없는경우
						selected_index = 0;
					}
					String item = model_routing.getElementAt(selected_index).toString();
					((IPLayer) m_LayerMgr.GetLayer("IP")).deleteRoutingEntry(selected_index);
				}
			}
		});
		routingManageButtonPanel.add(Delete_Button_Routing);
		// Routing Table Entry GUI - END

		// DON'T DELETE THIS
		setVisible(true);
	}

	class AddProxyDialog extends JDialog {
		JLabel DestinationLabel = new JLabel("Destination");
		JLabel NetmaskLabel = new JLabel("Netmask");
		JLabel GatewayLabel = new JLabel("Gateway");
		JLabel FlagLabel = new JLabel("Flag");
		JLabel InterfaceLabel = new JLabel("Interface");

		JTextField dest_tf = new JTextField();	// dest tf
		JTextField netmask_tf = new JTextField();	// netmask tf
		JTextField gateway_tf = new JTextField();	// gateway tf
		JTextField flag_tf = new JTextField();	// flag tf
		String ports[] = {"Port 1", "Port 2"};
		JComboBox<String> combo = new JComboBox<String>(ports);

		JButton OKButton;

		public AddProxyDialog(JFrame frame, String title) {
			super(frame, title);
			this.setLocationRelativeTo(frame);
			JPanel jp = new JPanel();

			JPanel subpanel = new JPanel();
			subpanel.add(DestinationLabel);
			subpanel.add(dest_tf);
			subpanel.add(NetmaskLabel);
			subpanel.add(netmask_tf);
			subpanel.add(GatewayLabel);
			subpanel.add(gateway_tf);
			subpanel.add(FlagLabel);
			subpanel.add(flag_tf);
			subpanel.add(InterfaceLabel);
			subpanel.add(combo);
			subpanel.setLayout(new GridLayout(5,2));

			BorderLayout bl = new BorderLayout();
			jp.setLayout(bl);
			jp.add(subpanel, BorderLayout.NORTH);
			OKButton = new JButton("OK");
			jp.add(OKButton, BorderLayout.SOUTH);


			add(jp);
			setSize(300, 220);
			setDefaultCloseOperation(DISPOSE_ON_CLOSE);

			OKButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					// TODO: 입력받은 정보를 Routing Entry 리스트에 추가 후 창을 닫음
					String dest = dest_tf.getText();
					String netmask = netmask_tf.getText();
					String gateway = gateway_tf.getText();
					String flag = flag_tf.getText();
					int interface_idx = combo.getSelectedIndex();

					String[] temp_strarr;

					temp_strarr = dest.split("\\.");
					byte[] dest_bytearr = new byte[4];
					for (int i = 0; i < 4; i++) {
						dest_bytearr[i] = (byte) Integer.parseInt(temp_strarr[i]);
					}

					temp_strarr = netmask.split("\\.");
					byte[] netmask_bytearr = new byte[4];
					for (int i = 0; i < 4; i++) {
						netmask_bytearr[i] = (byte) Integer.parseInt(temp_strarr[i]);
					}

					temp_strarr = gateway.split("\\.");
					byte[] gateway_bytearr = new byte[4];
					for (int i = 0; i < 4; i++) {
						gateway_bytearr[i] = (byte) Integer.parseInt(temp_strarr[i]);
					}

					// IPLayer Routing Table에 추가
					((IPLayer) m_LayerMgr.GetLayer("IP")).
							addRoutingEntry(dest_bytearr, netmask_bytearr, gateway_bytearr, flag, interface_idx);

					setVisible(false);	// 창 닫기
				}
			});
		}
	}


	class setAddressListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {

			if (e.getSource() == Setting_Button) { // Setting 버튼 클릭 이벤트 처리
				// TODO: Setting 버튼 클릭 이벤트 처리
				AddressTable.add(new AddressTableEntry(srcIpAddr1, srcMacAddr1));
				AddressTable.add(new AddressTableEntry(srcIpAddr2, srcMacAddr2));
				
				// Receive 실행
				((NILayer) m_LayerMgr.GetLayer("NI")).SetAdapterNumber(adapterNumber);
				((NILayer) m_LayerMgr.GetLayer("NI")).SetAdapterNumber(adapterNumber2);

				System.out.println("Source Addr Table has been updated.");

			}
		}
	}

	class sendButtonListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			if (e.getSource() == ARP_send_Button) { // ARP Send 버튼 클릭 이벤트 처리
				// ARP Send 버튼 클릭 이벤트 처리 1 - ARP Cache Table Update
				// ARPLayer에서 GUI Window update 함수 호출하는 것으로 대체

				// TODO: ARP Send 버튼 클릭 이벤트 처리 2 - 패킷 전송(Send) 구현
				String dstIP = targetIPWrite.getText();

				byte[] dstIP_bytearr = new byte[4];
				String[] byte_ip = dstIP.split("\\.");
				for (int i = 0; i < 4; i++) {
					dstIP_bytearr[i] = (byte) Integer.parseInt(byte_ip[i], 10);
				}
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).SetDstIPAddress(dstIP_bytearr);

				// AppLayer로 전송
				String input = "";	// data
				byte[] bytes = input.getBytes();
				((ApplicationLayer) m_LayerMgr.GetLayer("Application")).Send(bytes, bytes.length, dstIP);
			}
		}

	}

	public String get_MacAddress(byte[] byte_MacAddress) { //MAC Byte二쇱냼瑜� String�쑝濡� 蹂��솚
		String MacAddress = "";
		for (int i = 0; i < 6; i++) { 
			//2�옄由� 16吏꾩닔瑜� ��臾몄옄濡�, 洹몃━怨� 1�옄由� 16吏꾩닔�뒗 �븵�뿉 0�쓣 遺숈엫.
			MacAddress += String.format("%02X%s", byte_MacAddress[i], (i < MacAddress.length() - 1) ? "" : "");
			
			if (i != 5) {
				//2�옄由� 16吏꾩닔 �옄由� �떒�쐞 �뮘�뿉 "-"遺숈뿬二쇨린
				MacAddress += "-";
			}
		} 
		System.out.println("mac_address:" + MacAddress);
		return MacAddress;
	}

	public String get_IpAddress(byte[] byte_IpAddress) { //MAC Byte二쇱냼瑜� String�쑝濡� 蹂��솚
		String IpAddress = "";
		for (int i = 0; i < 4; i++) {
			//2�옄由� 16吏꾩닔瑜� ��臾몄옄濡�, 洹몃━怨� 1�옄由� 16吏꾩닔�뒗 �븵�뿉 0�쓣 遺숈엫.
			IpAddress += String.valueOf(byte_IpAddress[i] & 0xFF);

			if (i != 3) {
				//2�옄由� 16吏꾩닔 �옄由� �떒�쐞 �뮘�뿉 "-"遺숈뿬二쇨린
				IpAddress += ":";
			}
		}
		System.out.println("ip_address:" + IpAddress);
		return IpAddress;
	}

	public boolean Receive(byte[] input) { //硫붿떆吏� Receive
		// TODO: Receive 구현
		return true;
	}

	// GUI의 ARPCacheEntryWindow를 업데이트하는 함수
	public static void UpdateARPCacheEntryWindow(Hashtable<String, ARPLayer._ARP_Cache_Entry> table) {
		model_arp.removeAllElements();
		if(table.size() > 0) {
			for(Map.Entry<String, ARPLayer._ARP_Cache_Entry> e : table.entrySet()) {
				String targetIP = e.getKey();	// 타겟 IP 주소
				if(targetIP == null || targetIP.length() == 0)	return;

				String macAddr_string = "";
				byte[] macAddr_bytearray = e.getValue().addr;	// mac 주소
				if(macAddr_bytearray == null || macAddr_bytearray.length == 0) {
					// mac 주소 모르는 경우
					macAddr_string = "????????????";
				} else {
					// mac 주소 아는 경우=
					// : 붙이기
					macAddr_string += String.format("%02X", (0xFF & macAddr_bytearray[0])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[1])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[2])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[3])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[4])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[5]));
				}

				String status = e.getValue().status? "complete" : "incomplete";		// status 정보

				// Window에 표시될 최종 정보
				String itemText = String.format("%-20s %-20s %-20s", targetIP, macAddr_string, status);

				model_arp.addElement(itemText);
			}
		}
	}

	public static void UpdateRoutingTableWindow(ArrayList<IPLayer._ROUTING_ELEMENT> list) {
		model_routing.removeAllElements();
		if(list.size() > 0) {
			for(IPLayer._ROUTING_ELEMENT element : list) {
				String dest = ByteArrToIPString(element.dstAddress);
				String netmask = ByteArrToIPString(element.subnet);
				String gateway = ByteArrToIPString(element.gateway);
				String flag = element.flag;
				String interface_str = "";
				if(element.adaptNum == 0)
					interface_str = "Port 1";
				else
					interface_str = "Port 2";
				String itemText = String.format("%-20s %-20s %-20s %-20s %-20s", dest, netmask, gateway, flag, interface_str);
				model_routing.addElement(itemText);
			}
		}
	}

	public static String ByteArrToIPString(byte[] arr) {
		String ret = "";
		ret += String.valueOf(arr[0] & 0xFF) + "."
				+ String.valueOf(arr[1] & 0xFF) + "."
				+ String.valueOf(arr[2] & 0xFF) + "."
				+ String.valueOf(arr[3] & 0xFF);
		return ret;
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
		// nUpperLayerCount++;
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
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);

	}

}
