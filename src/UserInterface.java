import java.awt.*;
import java.awt.event.*;
import java.io.FileOutputStream;
import java.util.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import jpcap.NetworkInterface;
import jpcap.packet.ARPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import function.*;
import jpcap.packet.TCPPacket;

public class UserInterface extends JFrame{
    JMenuBar menubar;   //菜单条
    JMenu menuFile1,menuFile2; //菜单
    JMenuItem[] item;   //菜单项
    JMenuItem pro1,pro2,pro3,pro4,pro5,pro6;
    JTextField searchText;
    JButton sipButton,dipButton,searchButton,tcpButton;
    JPanel panel;
    JScrollPane scrollPane;
    JTable table;
    final String[] head = new String[] {
            "时间","源IP", "目的IP", "协议", "长度"
    };
    NetworkInterface[] devices;
    Object[][] datalist = {};
    DefaultTableModel tableModel;
    CapturePacket allpackets;
    public UserInterface(){
        allpackets = new CapturePacket();
        this.setTitle("ymly's Sniffer");
        this.setBounds(650, 150, 1200, 1000);
        menubar = new JMenuBar();
        //根据网卡进行过滤
        menuFile1 = new JMenu(" 选择网卡  ");
        NetworkInterface[] devices = new NetworkCard().getCardlists();
        item = new JMenuItem[devices.length];
        for (int i = 0; i < devices.length; i++) {
            item[i] = new JMenuItem(i + ": " + devices[i].name + "("
                    + devices[i].description  + ")");
            menuFile1.add(item[i]);
            item[i].addActionListener(
                    new CardActionListener(devices[i]));
        }
        //根据协议进行过滤
        menuFile2 = new JMenu("  协议筛选    ");
        pro3 = new JMenuItem("ICMP");
        pro4 = new JMenuItem("TCP");
        pro5 = new JMenuItem("UDP");
        pro2=new JMenuItem("HTTP/HTTPS");
        pro1=new JMenuItem("ARP");
        pro6=new JMenuItem("IP");
        pro3.addActionListener(
                new ActionListener(){
                    public void actionPerformed(ActionEvent e3) {
                        allpackets.setFilter("ICMPv6");
                        allpackets.clearpackets();
                        while(tableModel.getRowCount()>0){
                            tableModel.removeRow(tableModel.getRowCount()-1);
                        }

                    }
                });
        pro2.addActionListener(
                new ActionListener(){
                    public void actionPerformed(ActionEvent e3) {
                        allpackets.setFilter("HTTP");
                        allpackets.clearpackets();
                        while(tableModel.getRowCount()>0){
                            tableModel.removeRow(tableModel.getRowCount()-1);
                        }

                    }
                });
        pro4.addActionListener(
                new ActionListener(){
                    public void actionPerformed(ActionEvent e3) {
                        allpackets.setFilter("TCP");
                        allpackets.clearpackets();
                        while(tableModel.getRowCount()>0){
                            tableModel.removeRow(tableModel.getRowCount()-1);
                        }
                    }
                });
        pro5.addActionListener(
                new ActionListener(){
                    public void actionPerformed(ActionEvent e3) {
                        allpackets.setFilter("UDP");
                        allpackets.clearpackets();
                        while(tableModel.getRowCount()>0){
                            tableModel.removeRow(tableModel.getRowCount()-1);
                        }
                    }
                });
        pro1.addActionListener(
                new ActionListener(){
                    public void actionPerformed(ActionEvent e3) {
                        allpackets.setFilter("ARP");
                        allpackets.clearpackets();
                        while(tableModel.getRowCount()>0){
                            tableModel.removeRow(tableModel.getRowCount()-1);
                        }
                    }
                });
        pro6.addActionListener(
                new ActionListener(){
                    public void actionPerformed(ActionEvent e3) {
                        allpackets.setFilter("IP");
                        allpackets.clearpackets();
                        while(tableModel.getRowCount()>0){
                            tableModel.removeRow(tableModel.getRowCount()-1);
                        }

                    }
                });
        menuFile2.add(pro1);
        menuFile2.add(pro6);
        menuFile2.add(pro3);
        menuFile2.add(pro4);
        menuFile2.add(pro5);
        menuFile2.add(pro2);
        //根据源IP进行过滤
        sipButton = new JButton(" 源IP筛选");
        sipButton.addActionListener(
                new ActionListener(){
                    public void actionPerformed(ActionEvent e) {
                        String fsip = JOptionPane.showInputDialog("请输入源IP，以筛选数据包：");
                        allpackets.setFilter("sip "+fsip);
                        allpackets.clearpackets();
                        while(tableModel.getRowCount()>0){
                            tableModel.removeRow(tableModel.getRowCount()-1);
                        }
                    }
                });
        //根据目的IP进行过滤
        dipButton = new JButton(" 目的IP筛选 ");
        dipButton.addActionListener(
                new ActionListener(){
                    public void actionPerformed(ActionEvent e) {
                        String fdip = JOptionPane.showInputDialog("请输入目的IP，以筛选数据包：");
                        allpackets.setFilter("dip "+fdip);
                        allpackets.clearpackets();
                        while(tableModel.getRowCount()>0){
                            tableModel.removeRow(tableModel.getRowCount()-1);
                        }
                    }
                });
        //根据关键字进行过滤
        searchButton = new JButton(" 关键字筛选  ");
        searchButton.addActionListener(
                new ActionListener(){
                    public void actionPerformed(ActionEvent e) {
                        String fkeyword = JOptionPane.showInputDialog("请输入数据关键字，以筛选数据包：");
                        allpackets.setFilter("keyword "+fkeyword);
                        allpackets.clearpackets();
                        while(tableModel.getRowCount()>0){
                            tableModel.removeRow(tableModel.getRowCount()-1);
                        }
                    }
                });
       
        //将菜单添加到菜单条上
        menubar.add(menuFile1);
        menubar.add(menuFile2);
        menubar.add(sipButton);
        menubar.add(dipButton);
        menubar.add(searchButton);
        setJMenuBar(menubar);

        tableModel = new DefaultTableModel(datalist, head);
        table = new JTable(tableModel){
            public boolean isCellEditable(int row, int column){
                return false;
            }
        };
        allpackets.setTable(tableModel);
        table.setPreferredScrollableViewportSize(new Dimension(500, 60));// 设置表格的大小
        table.setRowHeight(35);// 设置每行的高度为35
        table.setRowMargin(8);// 设置相邻两行单元格的距离
        table.setRowSelectionAllowed(true);// 设置可否被选择.默认为false
        table.setSelectionBackground(Color.cyan);// 设置所选择行的背景色
        table.setSelectionForeground(Color.red);// 设置所选择行的前景色
        table.setShowGrid(true);// 是否显示网格线
        table.doLayout();
        scrollPane = new JScrollPane(table);
        panel = new JPanel(new GridLayout(0, 1));
        panel.setPreferredSize(new Dimension(600, 300));
        panel.setBackground(Color.black);
        panel.add(scrollPane);
        setContentPane(panel);
        pack();
        table.addMouseListener(new MouseAdapter(){
            public void mouseClicked(MouseEvent ev){
                if(ev.getClickCount() == 2){
                    int row = table.getSelectedRow();
                    JFrame frame = new JFrame("详细信息");
                    JPanel panel = new JPanel();
                    final JTextArea info = new JTextArea(23, 42);
                    info.setEditable(false);
                    info.setLineWrap(true);
                    info.setWrapStyleWord(true);
                    frame.add(panel);
                    panel.add(new JScrollPane(info));
                    JButton save = new JButton("保存到本地");
                    save.addActionListener(
                            new ActionListener(){
                                public void actionPerformed(ActionEvent e3) {
                                    String text = info.getText();
                                    int name = (int)System.currentTimeMillis();
                                    try {
                                        FileOutputStream fos = new FileOutputStream("d://"+name+".txt");
                                        fos.write(text.getBytes());
                                        fos.close();
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    }
                                }
                            });
                    panel.add(save);
                    frame.setBounds(150, 150, 500, 500);
                    frame.setVisible(true);
                    frame.setResizable(false);
                    ArrayList<Packet> packetlist = allpackets.getpacketlist();
                    Map<String,String> hm1 = new HashMap<String,String>();
                    Map<String,String> hm2 = new HashMap<String,String>();
                    Packet packet = packetlist.get(row);
                    hm1 = new PacketAnalyze(packet).IPanalyze();
                    hm2 = new PacketAnalyze(packet).packetClass();
                    if(packet.getClass().equals(ARPPacket.class))
                    {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------ARP头信息：-------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        for (Map.Entry<String, String> me : hm2.entrySet()) {
                            info.append(me.getKey() + " : " + me.getValue() + "\n");
                        }
                    }
                    else
                    {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------IP头信息：-------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");

                        for (Map.Entry<String, String> me1 : hm1.entrySet()) {
                            info.append(me1.getKey() + " : " + me1.getValue() + "\n");
                        }

                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-----------------------------" + hm2.get("协议") + "头信息：-----------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        for (Map.Entry<String, String> me : hm2.entrySet()) {
                            info.append(me.getKey() + " : " + me.getValue() + "\n");
                        }
                    }
                }
            }
        });

        setResizable(false);
        setVisible(true);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }

        });
    }

    private class CardActionListener implements ActionListener{

        NetworkInterface device;
        CardActionListener(NetworkInterface device){
            this.device = device;
        }
        public void actionPerformed(ActionEvent e) {
            allpackets.setDevice(device);
            allpackets.setFilter("");
            new Thread(allpackets).start();   //开启抓包线程
        }
    }
}