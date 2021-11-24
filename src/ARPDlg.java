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
	static DefaultListModel model_arp;	// �떎�젣 arp cache �뜲�씠�꽣
	JScrollPane scroll_arp;		// �뒪�겕濡� �냽�꽦(arp)
	JButton Item_Delete_Button;	// Item Delete 踰꾪듉
	JButton All_Delete_Button;	// All Delete 踰꾪듉
	private JTextField targetIPWrite;

	// Routing Table
	JList list_routing;			// routing table list
	static DefaultListModel model_routing;	// �떎�젣 routing table entry �뜲�씠�꽣
	JScrollPane scroll_routing;		// �뒪�겕濡� �냽�꽦
	JButton Add_Button_Routing;		// Add 踰꾪듉
	JButton Delete_Button_Routing;	// Delete 踰꾪듉
	JDialog addDialog;			// add routing entry �떎�씠�뼹濡쒓렇

	// Source Address Setting
	JButton Setting_Button;		// Source MAC, IP �꽭�똿 踰꾪듉
	JButton ARP_send_Button;	// ARP �뙣�궥 �쟾�넚 踰꾪듉
	static JComboBox<String> NICComboBox;	// �옖移대뱶 �꽑�깮 ComboBox
	static JComboBox<String> NICComboBox2;	// �옖移대뱶 �꽑�깮 ComboBox2

	// �엫�떆 蹂��닔
	byte[] srcMacAddr1;
	byte[] srcIpAddr1;
	byte[] srcMacAddr2;
	byte[] srcIpAddr2;
	// �엫�떆 蹂��닔

	int adapterNumber = 0;
	int adapterNumber2 = 0;

	public static void main(String[] args) {

		// 紐⑤뱺 �젅�씠�뼱 異붽� 諛� �뿰寃�
		// �븯�쐞 怨꾩링�쓽 �닚�꽌瑜� �젙�븿
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
		list_arp_cache.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);	// �븯�굹留� �꽑�깮媛��뒫�븯�룄濡�
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
					if(selected_index < 0) {	// �꽑�깮�맂 �빆紐⑹씠 �뾾�뒗 寃쎌슦 �삁�쇅泥섎━
						if(model_arp.size() == 0) return;	// �븘臾닿쾬�룄 �뾾�뒗寃쎌슦
						selected_index = 0;
					}
					String item = model_arp.getElementAt(selected_index).toString();
					ARPLayer.deleteARPEntry(item.substring(0,19).trim());	// IP二쇱냼留� �옒�씪�꽌 key濡� �쟾�떖
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
					// TODO: �쟾泥� �빆紐� �궘�젣 - DONE
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
		JLabel targetIPLabel = new JLabel("IP 二쇱냼");
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
//		lblsrcMAC.setBounds(10, 80, 170, 20); //占쎌맄燁삼옙 筌욑옙占쎌젟
//		srcAddrSettingPanel.add(lblsrcMAC); //panel �빊遺쏙옙
//
//		srcMacAddress = new JTextArea();
//		srcMacAddress.setBounds(10, 105, 170, 20);
//		srcMacAddress.setBorder(BorderFactory.createLineBorder(Color.black));
//		srcAddrSettingPanel.add(srcMacAddress);// src address

		Setting_Button = new JButton("Setting");// setting
		Setting_Button.setBounds(200, 80, 130, 20);
		Setting_Button.addActionListener(new setAddressListener());
		srcAddrSettingPanel.add(Setting_Button);// setting

		// NILayer濡쒕��꽣 �옖移대뱶 �젙蹂� 媛��졇�삤湲�
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
					get_MacAddress(srcMacAddr);	// print �슜�룄
					get_IpAddress(srcIpAddr);	// print �슜�룄

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
					get_MacAddress(srcMacAddr);	// print �슜�룄
					get_IpAddress(srcIpAddr);	// print �슜�룄

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
		list_routing.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);	// �븯�굹留� �꽑�깮媛��뒫�븯�룄濡�
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
		addDialog = new AddProxyDialog(this, "Routing Table Entry 異붽�");	// 異붽� dialog
		Add_Button_Routing.addActionListener(new ActionListener () {
			// Routing Table Entry 異붽� �떎�씠�뼹濡쒓렇 �쓣�슦湲�
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
				// TODO: Delete 踰꾪듉 �겢由� �씠踰ㅽ듃 泥섎━ - DONE
				if(e.getSource() == Delete_Button_Routing) {
					int selected_index = list_routing.getSelectedIndex();
					if(selected_index < 0) {	// �꽑�깮�맂 �빆紐⑹씠 �뾾�뒗 寃쎌슦 �삁�쇅泥섎━
						if(model_routing.size() == 0) return;	// �븘臾닿쾬�룄 �뾾�뒗寃쎌슦
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
					// TODO: �엯�젰諛쏆� �젙蹂대�� Routing Entry 由ъ뒪�듃�뿉 異붽� �썑 李쎌쓣 �떕�쓬
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

					// IPLayer Routing Table�뿉 異붽�
					((IPLayer) m_LayerMgr.GetLayer("IP")).
							addRoutingEntry(dest_bytearr, netmask_bytearr, gateway_bytearr, flag, interface_idx);

					setVisible(false);	// 李� �떕湲�
				}
			});
		}
	}


	class setAddressListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {

			if (e.getSource() == Setting_Button) { // Setting 踰꾪듉 �겢由� �씠踰ㅽ듃 泥섎━
				// TODO: Setting 踰꾪듉 �겢由� �씠踰ㅽ듃 泥섎━
				AddressTable.add(new AddressTableEntry(srcIpAddr1, srcMacAddr1));
				AddressTable.add(new AddressTableEntry(srcIpAddr2, srcMacAddr2));
				
				// Receive �떎�뻾
				((NILayer) m_LayerMgr.GetLayer("NI")).SetAdapterNumber(adapterNumber);
				((NILayer) m_LayerMgr.GetLayer("NI")).SetAdapterNumber(adapterNumber2);

				System.out.println("Source Addr Table has been updated.");

			}
		}
	}

	class sendButtonListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			if (e.getSource() == ARP_send_Button) { // ARP Send 踰꾪듉 �겢由� �씠踰ㅽ듃 泥섎━
				// ARP Send 踰꾪듉 �겢由� �씠踰ㅽ듃 泥섎━ 1 - ARP Cache Table Update
				// ARPLayer�뿉�꽌 GUI Window update �븿�닔 �샇異쒗븯�뒗 寃껋쑝濡� ��泥�

				// TODO: ARP Send 踰꾪듉 �겢由� �씠踰ㅽ듃 泥섎━ 2 - �뙣�궥 �쟾�넚(Send) 援ы쁽
				String dstIP = targetIPWrite.getText();

				byte[] dstIP_bytearr = new byte[4];
				String[] byte_ip = dstIP.split("\\.");
				for (int i = 0; i < 4; i++) {
					dstIP_bytearr[i] = (byte) Integer.parseInt(byte_ip[i], 10);
				}
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).SetDstIPAddress(dstIP_bytearr);

				// AppLayer濡� �쟾�넚
				String input = "";	// data
				byte[] bytes = input.getBytes();
				((ApplicationLayer) m_LayerMgr.GetLayer("Application")).Send(bytes, bytes.length, dstIP);
			}
		}

	}

	public String get_MacAddress(byte[] byte_MacAddress) { //MAC Byte雅뚯눘�꺖�몴占� String占쎌몵嚥∽옙 癰귨옙占쎌넎
		String MacAddress = "";
		for (int i = 0; i < 6; i++) { 
			//2占쎌쁽�뵳占� 16筌욊쑴�땾�몴占� 占쏙옙�눧紐꾩쁽嚥∽옙, 域밸챶�봺�⑨옙 1占쎌쁽�뵳占� 16筌욊쑴�땾占쎈뮉 占쎈링占쎈퓠 0占쎌뱽 �겫�늿�뿫.
			MacAddress += String.format("%02X%s", byte_MacAddress[i], (i < MacAddress.length() - 1) ? "" : "");
			
			if (i != 5) {
				//2占쎌쁽�뵳占� 16筌욊쑴�땾 占쎌쁽�뵳占� 占쎈뼊占쎌맄 占쎈츟占쎈퓠 "-"�겫�늿肉т틠�눊由�
				MacAddress += "-";
			}
		} 
		System.out.println("mac_address:" + MacAddress);
		return MacAddress;
	}

	public String get_IpAddress(byte[] byte_IpAddress) { //MAC Byte雅뚯눘�꺖�몴占� String占쎌몵嚥∽옙 癰귨옙占쎌넎
		String IpAddress = "";
		for (int i = 0; i < 4; i++) {
			//2占쎌쁽�뵳占� 16筌욊쑴�땾�몴占� 占쏙옙�눧紐꾩쁽嚥∽옙, 域밸챶�봺�⑨옙 1占쎌쁽�뵳占� 16筌욊쑴�땾占쎈뮉 占쎈링占쎈퓠 0占쎌뱽 �겫�늿�뿫.
			IpAddress += String.valueOf(byte_IpAddress[i] & 0xFF);

			if (i != 3) {
				//2占쎌쁽�뵳占� 16筌욊쑴�땾 占쎌쁽�뵳占� 占쎈뼊占쎌맄 占쎈츟占쎈퓠 "-"�겫�늿肉т틠�눊由�
				IpAddress += ":";
			}
		}
		System.out.println("ip_address:" + IpAddress);
		return IpAddress;
	}

	public boolean Receive(byte[] input) { //筌롫뗄�뻻筌욑옙 Receive
		// TODO: Receive 援ы쁽
		return true;
	}

	// GUI�쓽 ARPCacheEntryWindow瑜� �뾽�뜲�씠�듃�븯�뒗 �븿�닔
	public static void UpdateARPCacheEntryWindow(Hashtable<String, ARPLayer._ARP_Cache_Entry> table) {
		model_arp.removeAllElements();
		if(table.size() > 0) {
			for(Map.Entry<String, ARPLayer._ARP_Cache_Entry> e : table.entrySet()) {
				String targetIP = e.getKey();	// ��寃� IP 二쇱냼
				if(targetIP == null || targetIP.length() == 0)	return;

				String macAddr_string = "";
				byte[] macAddr_bytearray = e.getValue().addr;	// mac 二쇱냼
				if(macAddr_bytearray == null || macAddr_bytearray.length == 0) {
					// mac 二쇱냼 紐⑤Ⅴ�뒗 寃쎌슦
					macAddr_string = "????????????";
				} else {
					// mac 二쇱냼 �븘�뒗 寃쎌슦=
					// : 遺숈씠湲�
					macAddr_string += String.format("%02X", (0xFF & macAddr_bytearray[0])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[1])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[2])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[3])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[4])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[5]));
				}

				String status = e.getValue().status? "complete" : "incomplete";		// status �젙蹂�

				// Window�뿉 �몴�떆�맆 理쒖쥌 �젙蹂�
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
