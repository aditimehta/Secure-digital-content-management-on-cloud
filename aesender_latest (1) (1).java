import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.util.*;
import java.io.*;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.*;

class aesvelocity extends JFrame implements ActionListener{
    static JPanel panel;
    static JTextArea input,enc,dec,velocity,key,geo_key,enc1,location,key1,ran,file_path,enc_path,time;
    static JButton enc_button,dec_button,ran_button,open_button,select_enc_button,upload_button,end_button;
    static JLabel encryption,decryption;

    char [] textData= new char[1000];

    static String data,final_data;
    private JButton open = new JButton("Open");

    private static final String CHAR_LIST =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    private static final int RANDOM_STRING_LENGTH = 32;

    public aesvelocity(){
        initUI();
    }


    public final void initUI(){
        panel = new JPanel();
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.setLayout(new FlowLayout(FlowLayout.CENTER));
        JLabel encryption = new JLabel("                    Encryption                    ");
        encryption.setFont(new Font("Arial", Font.PLAIN, 20));
        panel.add(encryption);

       panel.add(new JLabel("                                    "));
       open_button = new JButton("  Get file  ");
       panel.add(open_button,BorderLayout.CENTER);
       open_button.addActionListener(this);
       add(panel);


       panel.add(new JLabel("                                               "));
       panel.add(new JLabel("      File path"));
       file_path = new JTextArea(1,25);
       panel.add(file_path);

       // panel.add(new JLabel("                                                                                                             "));
        panel.add(new JLabel("      Location"));
        location = new JTextArea(1,25);
        panel.add(location);

       panel.add(new JLabel("        Time"));
       time = new JTextArea(1,25);
       panel.add(time);

       panel.add(new JLabel("                           "));
       ran_button = new JButton("Get random key");
       panel.add(ran_button,BorderLayout.CENTER);
       ran_button.addActionListener(this);
       panel.add(new JLabel("                        "));

      //  panel.add(new JLabel("                           "));
       panel.add(new JLabel("Random key"));
       ran = new JTextArea(1,25);
       panel.add(ran);

        panel.add(new JLabel("      Geo-Key"));
        geo_key = new JTextArea(1,25);
        panel.add(geo_key);

       /* panel.add(new JLabel("CipherText"));
        enc = new JTextArea(3,25);
        enc.setLineWrap(true);
        panel.add(enc);*/

        panel.add(new JLabel("                           "));
        enc_button = new JButton("  Encrypt data  ");
        enc_button.addActionListener(this);
        panel.add(enc_button,BorderLayout.CENTER);
       panel.add(new JLabel("                           "));

        panel.add(new JLabel("                           "));
        select_enc_button = new JButton("  Select file for encryption  ");
        select_enc_button.addActionListener(this);
        panel.add(select_enc_button,BorderLayout.CENTER);
        panel.add(new JLabel("                           "));

         panel.add(new JLabel("      File path"));
        enc_path = new JTextArea(1,25);
        panel.add(enc_path);

        panel.add(new JLabel("   "));
       upload_button = new JButton("Upload");
       panel.add(upload_button,BorderLayout.CENTER);
       upload_button.addActionListener(this);

       panel.add(new JLabel("                           "));
       end_button = new JButton("  Close  ");
       end_button.addActionListener(this);
       panel.add(end_button,BorderLayout.CENTER);


        setTitle("AES Encryption");
        setSize(400, 420);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
    }

	public void actionPerformed(ActionEvent ae){

	if(ae.getSource()==ran_button){
    			ran.setText(generateRandomString());
    		}

    if(ae.getSource()==open_button){
    			run(new FileChooserTest(), 250, 110);
    		}



     if(ae.getSource()==end_button){
					System.exit(0);
     	    }

	if(ae.getSource()==enc_button){
				System.out.println(time);
		        call_encrypt(data,location.getText(),ran.getText(),time.getText());
				//enc.setText(call_encrypt(data,location.getText(),ran.getText()));
	}
	if(ae.getSource()==select_enc_button){
					run1(new FileChooserTest1(), 250, 110);
	}

	if(ae.getSource()==upload_button){
					URLConnectionReader();
	}


	}


    public static void main(String[] args) {
         try {
        	SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                aesvelocity ex = new aesvelocity();
                ex.setVisible(true);
            }
            });
        }catch(Exception e){}
    }

    public void run(JFrame frame, int width, int height) {
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.setSize(width, height);
    frame.setVisible(true);
  }

  public void run1(JFrame frame, int width, int height) {
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.setSize(width, height);
    frame.setVisible(true);
  }

    public static void call_encrypt(String s,String loc,String time,String rand_key){
    	System.out.println(s);
    	byte loc_bytes[] = stringToKey(loc);
    	byte time_bytes[]= stringToKey(time);
    	byte random_key[] = stringToKey(rand_key);
    	byte final_key[] = xor_func1(random_key,loc_bytes,time_bytes);

    	geo_key.setText(bytesToHex(final_key));
    	byte returned[] = encrypt(s.getBytes(),final_key);
      String final_cipher=bytesToHex(returned);
       final_data=final_cipher;

    	//return bytesToHex(returned);
    }

    public static byte[] stringToKey(String s){
    	s = s.concat("00000000000000000000000000000000");
    	s = s.substring(0,32);
    	 s.getBytes();
    	System.out.println(s);
    	return s.getBytes();
    }

    public static String getRandomHexString(int numchars){
        Random r = new Random();
        StringBuffer sb = new StringBuffer();
        while(sb.length() < numchars){
            sb.append(Integer.toHexString(r.nextInt()));
        }
        return sb.toString().substring(0, numchars);
    }

    public static String bytesToHex(byte[] bytes) {
    	char[] hexChars = new char[bytes.length * 2];
 	   	for ( int j = 0; j < bytes.length; j++ ) {
    	    int v = bytes[j] & 0xff;
        	hexChars[j * 2] = hexArray[v >>> 4];
       	 	hexChars[j * 2 + 1] = hexArray[v & 0x0f];
    	}
    	return new String(hexChars);
	}

	public static byte[] hexToBytes(String s) {
    	int len = s.length();
    	byte[] data = new byte[len / 2];
    	for (int i = 0; i < len; i += 2) {
        	data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
    	}
	    return data;
	}

	final protected static char[] hexArray = "0123456789abcdef".toCharArray();
 	private static int Nb, Nk, Nr;
	private static byte[][] w;

	private static int[] sbox = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F,
			0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82,
			0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C,
			0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
			0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23,
			0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27,
			0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52,
			0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
			0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58,
			0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9,
			0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92,
			0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
			0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E,
			0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
			0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0,
			0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62,
			0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E,
			0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78,
			0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B,
			0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
			0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98,
			0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55,
			0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41,
			0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

	private static int Rcon[] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
		0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
		0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
		0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
		0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
		0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
		0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
		0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
		0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
		0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
		0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
		0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
		0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
		0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
		0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
		0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };

	private static byte[] xor_func(byte[] a, byte[] b) {
		byte[] out = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			out[i] = (byte) (a[i] ^ b[i]);
		}
		return out;

	}


		private static byte[] xor_func1(byte[] a, byte[] b,byte[] c) {
		byte[] out1 = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			out1[i] = (byte) (a[i] ^ b[i] ^ c[i]);
		}
		return out1;

	}









	private static byte[][] generateSubkeys(byte[] key) {
		byte[][] tmp = new byte[Nb * (Nr + 1)][4];

		int i = 0;
		while (i < Nk) {

			tmp[i][0] = key[i * 4];
			tmp[i][1] = key[i * 4 + 1];
			tmp[i][2] = key[i * 4 + 2];
			tmp[i][3] = key[i * 4 + 3];
			i++;
		}
		i = Nk;
		while (i < Nb * (Nr + 1)) {
			byte[] temp = new byte[4];
			for(int k = 0;k<4;k++)
				temp[k] = tmp[i-1][k];
			if (i % Nk == 0) {
				temp = SubWord(rotateWord(temp));
				temp[0] = (byte) (temp[0] ^ (Rcon[i / Nk] & 0xff));
			} else if (Nk > 6 && i % Nk == 4) {
				temp = SubWord(temp);
			}
			tmp[i] = xor_func(tmp[i - Nk], temp);
			i++;
		}

		return tmp;
	}

	private static byte[] SubWord(byte[] in) {
		byte[] tmp = new byte[in.length];

		for (int i = 0; i < tmp.length; i++)
			tmp[i] = (byte) (sbox[in[i] & 0x000000ff] & 0xff);

		return tmp;
	}

	private static byte[] rotateWord(byte[] input) {
		byte[] tmp = new byte[input.length];
		tmp[0] = input[1];
		tmp[1] = input[2];
		tmp[2] = input[3];
		tmp[3] = input[0];

		return tmp;
	}

	private static byte[][] AddRoundKey(byte[][] state, byte[][] w, int round) {

		byte[][] tmp = new byte[state.length][state[0].length];

		for (int c = 0; c < Nb; c++) {
			for (int l = 0; l < 4; l++)
				tmp[l][c] = (byte) (state[l][c] ^ w[round * Nb + c][l]);
		}

		return tmp;
	}

	private static byte[][] SubBytes(byte[][] state) {

		byte[][] tmp = new byte[state.length][state[0].length];
		for (int row = 0; row < 4; row++)
			for (int col = 0; col < Nb; col++)
				tmp[row][col] = (byte) (sbox[(state[row][col] & 0x000000ff)] & 0xff);

		return tmp;
	}

	private static byte[][] ShiftRows(byte[][] state) {

		byte[] t = new byte[4];
		for (int r = 1; r < 4; r++) {
			for (int c = 0; c < Nb; c++)
				t[c] = state[r][(c + r) % Nb];
			for (int c = 0; c < Nb; c++)
				state[r][c] = t[c];
		}

		return state;
	}

	private static byte[][] MixColumns(byte[][] s){
		 int[] sp = new int[4];
	      byte b02 = (byte)0x02, b03 = (byte)0x03;
	      for (int c = 0; c < 4; c++) {
	         sp[0] = FFMul(b02, s[0][c]) ^ FFMul(b03, s[1][c]) ^ s[2][c]  ^ s[3][c];
	         sp[1] = s[0][c]  ^ FFMul(b02, s[1][c]) ^ FFMul(b03, s[2][c]) ^ s[3][c];
	         sp[2] = s[0][c]  ^ s[1][c]  ^ FFMul(b02, s[2][c]) ^ FFMul(b03, s[3][c]);
	         sp[3] = FFMul(b03, s[0][c]) ^ s[1][c]  ^ s[2][c]  ^ FFMul(b02, s[3][c]);
	         for (int i = 0; i < 4; i++) s[i][c] = (byte)(sp[i]);
	      }

	      return s;
	}

	public static byte FFMul(byte a, byte b) {
		byte aa = a, bb = b, r = 0, t;
		while (aa != 0) {
			if ((aa & 1) != 0)
				r = (byte) (r ^ bb);
			t = (byte) (bb & 0x80);
			bb = (byte) (bb << 1);
			if (t != 0)
				bb = (byte) (bb ^ 0x1b);
			aa = (byte) ((aa & 0xff) >> 1);
		}
		return r;
	}

	public static byte[] encryptBloc(byte[] in) {
		byte[] tmp = new byte[in.length];



		byte[][] state = new byte[4][Nb];

		for (int i = 0; i < in.length; i++)
			state[i / 4][i % 4] = in[i%4*4+i/4];

		state = AddRoundKey(state, w, 0);
		for (int round = 1; round < Nr; round++) {
			state = SubBytes(state);
			state = ShiftRows(state);
			state = MixColumns(state);
			state = AddRoundKey(state, w, round);
		}
		state = SubBytes(state);
		state = ShiftRows(state);
		state = AddRoundKey(state, w, Nr);

		for (int i = 0; i < tmp.length; i++)
			tmp[i%4*4+i/4] = state[i / 4][i%4];

		return tmp;
	}

//Encryption block
	public static byte[] encrypt(byte[] in,byte[] key){

		Nb = 4;
		Nk = key.length/4;
		Nr = Nk + 6;


		int lenght=0;
		byte[] padding = new byte[1];
		int i;
		lenght = 16 - in.length % 16;
		padding = new byte[lenght];
		padding[0] = (byte) 0x80;

		for (i = 1; i < lenght; i++)
			padding[i] = 0;

		byte[] tmp = new byte[in.length + lenght];
		byte[] bloc = new byte[16];


		w = generateSubkeys(key);

		int count = 0;

		for (i = 0; i < in.length + lenght; i++) {
			if (i > 0 && i % 16 == 0) {
				bloc = encryptBloc(bloc);
				System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
			}
			if (i < in.length)
				bloc[i % 16] = in[i];
			else{
				bloc[i % 16] = padding[count % 16];
				count++;
			}
		}
		if(bloc.length == 16){
			bloc = encryptBloc(bloc);
			System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
		}

		return tmp;
	}


	private static byte[] deletePadding(byte[] input) {
		int count = 0;

		int i = input.length - 1;
		while (input[i] == 0) {
			count++;
			i--;
		}

		byte[] tmp = new byte[input.length - count - 1];
		System.arraycopy(input, 0, tmp, 0, tmp.length);
		return tmp;
	}


    /**
     * This method generates random string
     * @return
     */
    public String generateRandomString(){

        StringBuffer randStr = new StringBuffer();
        for(int i=0; i<RANDOM_STRING_LENGTH; i++){
            int number = getRandomNumber();
            char ch = CHAR_LIST.charAt(number);
            randStr.append(ch);
        }
        return randStr.toString();
    }

    /**
     * This method generates random numbers
     * @return int
     */
    private int getRandomNumber() {
        int randomInt = 0;
        Random randomGenerator = new Random();
        randomInt = randomGenerator.nextInt(CHAR_LIST.length());
        if (randomInt - 1 == -1) {
            return randomInt;
        } else {
            return randomInt - 1;
        }



        }


//For selecting first file

  public class FileChooserTest extends JFrame {
  public JTextField dir = new JTextField();
  public String path;


    public FileChooserTest() {
  	JButton open = new JButton("Open");
    JPanel p = new JPanel();
    open.addActionListener(new OpenL());
    p.add(open);

    JButton close = new JButton("Close");
    close.addActionListener(new CloseL());
    p.add(close);


    Container cp = getContentPane();
    cp.add(p, BorderLayout.SOUTH);
    dir.setEditable(false);

    p = new JPanel();
    p.setLayout(new GridLayout(2, 1));

    p.add(dir);
    cp.add(p, BorderLayout.NORTH);
  }



  class OpenL implements ActionListener {

    public void actionPerformed(ActionEvent e) {
      JFileChooser c = new JFileChooser();

      int rVal = c.showOpenDialog(FileChooserTest.this);
      if (rVal == JFileChooser.APPROVE_OPTION) {
        dir.setText(c.getCurrentDirectory().toString()+ "\\" + (c.getSelectedFile().getName()));
        path=c.getCurrentDirectory().toString()+ "\\" + (c.getSelectedFile().getName());
        file_path.setText(path);
        //System.out.println(path);


        try
        {
        	getdata(path);
        }
        catch(Exception e1)
        {
        }

       }

      if (rVal == JFileChooser.CANCEL_OPTION) {

        dir.setText("");
      }
    }
  }

  public void getdata(String path)throws IOException
  {
  	try
  	{


  		FileReader fr= new FileReader(path);
  			BufferedReader br = new BufferedReader(fr);
  			int n=4,i;
  			String line=null;
			while((line = br.readLine()) != null) {
                 	data=data+line;
            }



  	data = data.substring(1, data.length()-1).replaceAll(",", "");
  	//enc1.setText(data);
  	 // Always close files.
	br.close();
  }
  		catch(Exception e)
  		{
  		}
  }


class CloseL implements ActionListener {

  	public void actionPerformed(ActionEvent e) {

          setVisible(false);

}
  }



}


//For selecting the second file after encrypting data


public class FileChooserTest1 extends JFrame {
  public JTextField dir = new JTextField();
  public String path1;


    public FileChooserTest1() {
  	JButton open = new JButton("Open");
    JPanel p = new JPanel();
    open.addActionListener(new OpenL());
    p.add(open);


    JButton close = new JButton("Close");
    close.addActionListener(new CloseL());
    p.add(close);


    Container cp = getContentPane();
    cp.add(p, BorderLayout.SOUTH);
    dir.setEditable(false);

    p = new JPanel();
    p.setLayout(new GridLayout(2, 1));

    p.add(dir);
    cp.add(p, BorderLayout.NORTH);
  }



  class OpenL implements ActionListener {

    public void actionPerformed(ActionEvent e) {
      JFileChooser c = new JFileChooser();

      int rVal = c.showOpenDialog(FileChooserTest1.this);
      if (rVal == JFileChooser.APPROVE_OPTION) {
        dir.setText(c.getCurrentDirectory().toString()+ "\\" + (c.getSelectedFile().getName()));
        path1=c.getCurrentDirectory().toString()+ "\\" + (c.getSelectedFile().getName());
        enc_path.setText(path1);


        try
        {
        	setdata(path1);
        }
        catch(Exception e1)
        {
        }

       }

      if (rVal == JFileChooser.CANCEL_OPTION) {

        dir.setText("");
      }
    }
  }

  public void setdata(String path1)throws IOException
  {

  		try {

			String content=final_data;
			System.out.println(final_data);
			File file = new File(path1);

			// if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}

			FileWriter fw = new FileWriter(file.getAbsoluteFile());
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(content);
			bw.close();

			System.out.println("Done");

		} catch (IOException e) {
			e.printStackTrace();
		}



}

class CloseL implements ActionListener {

  	public void actionPerformed(ActionEvent e) {

          setVisible(false);

}
  }



}
public static void URLConnectionReader()
{

 try
        {
            Desktop.getDesktop().browse(new URL("http://www.gmail.com").toURI());
        }
        catch (Exception e) {}

}
}
