package function;
import jpcap.*;
public class NetworkCard {
    String[] cardlists;
    public static NetworkInterface[] getCardlists(){
        NetworkInterface[] cardlists=JpcapCaptor.getDeviceList();
        return cardlists;
    }

}
