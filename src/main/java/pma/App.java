package pma;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.awt.Color;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

/**
 * Hello world!
 *
 */
public class App extends JFrame {

	JTextField pathpk = new JTextField();
	JTextField pathmsg = new JTextField();
	JTextArea textInput = new JTextArea();
	String param = "secp256r1";
	private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    /* *** LAUNCHER *** */
    public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					new App();
				} catch (Exception e) { }
			}
		});
	}
    /* *** CONSTRUCTOR *** */
    public App() {
		this.setWindowsStyle();
		this.initComponents();
	}
    /** Set JFileChooser to Windows interface */
	
	private void setWindowsStyle() {
		try {
			try {
				UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
			} catch (InstantiationException e) { } 
			  catch (IllegalAccessException e) { } 
			  catch (UnsupportedLookAndFeelException e) { }	
		} catch (ClassNotFoundException e) { }
	}
	
	/** Initialize all frame components */
	
	private void initComponents() {	
		setResizable(false);
		setVisible(true);
		setTitle("ECC Messenger");
		setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
		setBounds(100, 100, 720, 740);
		addWindowListener(new WindowListener() {
			@Override
			public void windowActivated(WindowEvent e) { }

			@Override
			public void windowClosed(WindowEvent e) { }

			@Override
			public void windowClosing(WindowEvent e) {
				exit();
			}

			@Override
			public void windowDeactivated(WindowEvent e) { }

			@Override
			public void windowDeiconified(WindowEvent e) { }

			@Override
			public void windowIconified(WindowEvent e) { }

			@Override
			public void windowOpened(WindowEvent e) { }
		});
		
		
		InputStream stream = this.getClass().getResourceAsStream("/app_icon.png");
		try {
			this.setIconImage(ImageIO.read(stream));
		} catch (IOException e) { }
		
		JPanel contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		URL url = this.getClass().getResource("/ub_logo.png");
		ImageIcon image = new ImageIcon(url);
		JLabel label = new JLabel("", image, JLabel.CENTER);
		label.setBounds(0, 5, 280, 78);
		
		JPanel imagePanel = new JPanel();
		imagePanel.setLayout(null);
		imagePanel.add(label);
		imagePanel.setBounds(10, 11, 275, 78);
		contentPane.add(imagePanel);
		
		JPanel backPanel = new JPanel();
		backPanel.setBorder(new TitledBorder(null, "", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		backPanel.setBounds(500, 11, 190, 78);
		contentPane.add(backPanel);
		backPanel.setLayout(null);		
		
		JPanel dataPanel = new JPanel();			
		dataPanel.setBorder(new TitledBorder(null, "", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		dataPanel.setBounds(10, 100, 680, 491);
		contentPane.add(dataPanel);
		dataPanel.setLayout(null);
		
		JLabel welcome = new JLabel("ECC Messenger. Developed in 2022");
		welcome.setBounds(10, 11, 720, 14);
		dataPanel.add(welcome);
		welcome.setEnabled(false);
					
		JLabel labelpk = new JLabel("PK Path:");
		labelpk.setBounds(10, 45, 91, 18);
		dataPanel.add(labelpk);

		pathpk.setBounds(71, 42, 560, 22);		
		dataPanel.add(pathpk);

		JButton btsearch1 = new JButton(". . .");
		btsearch1.setBounds(639, 44, 33, 18);
		dataPanel.add(btsearch1);
		btsearch1.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser fc = new JFileChooser(); 
				int returnVal = fc.showOpenDialog(App.this);

     		   if (returnVal == JFileChooser.APPROVE_OPTION) {
         		File file = fc.getSelectedFile();
				pathpk.setText(file.toString());
         		   
       			 } else {
        		    
					showError("Failed to select PK");
				}
				
			}
		});  
     
		JLabel labelmsg = new JLabel("Message:");
		labelmsg.setBounds(10, 77, 66, 18);
		dataPanel.add(labelmsg);
		
		pathmsg.setBounds(71, 73, 560, 22);
		dataPanel.add(pathmsg);

		JButton btsearch2 = new JButton(". . .");
		btsearch2.setBounds(639, 75, 33, 18);
		dataPanel.add(btsearch2);
		btsearch2.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser fc = new JFileChooser(); 
				int returnVal = fc.showOpenDialog(App.this);

     		   if (returnVal == JFileChooser.APPROVE_OPTION) {
         		File file = fc.getSelectedFile();
				pathmsg.setText(file.toString());         		 
       			 } else {        		    
					showError("Failed to select MSG");
				}				
			}
		});		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(10, 120, 660, 350);
		dataPanel.add(scrollPane);		
		scrollPane.setViewportView(textInput);
		
		JPanel buttonPanel = new JPanel();
		buttonPanel.setBorder(new TitledBorder(null, "", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		buttonPanel.setBounds(10, 601, 680, 80);
		contentPane.add(buttonPanel);
		buttonPanel.setLayout(null);
		
		JButton genPK = new JButton("Generate PKCertificate");
		customizeButton(this, genPK);
		genPK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					genpk();					
				} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException
						| NoSuchProviderException | InvalidAlgorithmParameterException | KeyStoreException
						| CertificateException | UnrecoverableEntryException | IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}				
            }				
		});
		genPK.setBounds(10, 11, 170, 56);
		backPanel.add(genPK);

		JButton buttonRead = new JButton("Read");
		buttonRead.setBounds(10, 11, 300, 58);
		buttonRead.setFocusable(true);
		buttonPanel.add(buttonRead);
		customizeButton(this, buttonRead);
		buttonRead.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				File f1 = new File(pathmsg.getText().trim());
				File f2 = new File(pathpk.getText().trim());
				if(!f1.exists() || !f2.exists()) {
					showpop("Public Key and/or message not found", "Error");
			
				}else{
					try {					
						String msg = readmsg(pathmsg.getText().trim(), pathpk.getText().trim());
						textInput.setText(msg);
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidKeyException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidKeySpecException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchProviderException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (GeneralSecurityException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
			}
		});		
		JButton buttonWrite = new JButton("Write");
		buttonWrite.setBounds(370, 11, 300, 58);
		buttonWrite.setFocusable(true);
		buttonPanel.add(buttonWrite);
		customizeButton(this, buttonWrite);
		buttonWrite.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					writemsg(pathmsg.getText().trim(), pathpk.getText().trim(), textInput.getText().trim());
					textInput.setText("File enciphered at: "+ returnfilepath(pathmsg.getText().trim())+ "\n");
				} catch (IOException | GeneralSecurityException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});		
	}

	private void customizeButton(JFrame frame, JButton button) {
		button.setBackground(new Color(0, 25, 51)); /* Facebook RGB (59, 89, 182) */
		button.setForeground(Color.BLACK);
		button.setFocusPainted(false);
		frame.setFont(new Font("Tahoma", Font.BOLD, 12));
	}

	/** Ask if we want to close application */
	
	private void exit() {
		Object [] options = { "Yes", "No" };
		int option = JOptionPane.showOptionDialog(this, "Do you want to exit?", "Exit", 
				JOptionPane.YES_NO_OPTION, JOptionPane.INFORMATION_MESSAGE, null, 
				options, options[0]);
		if (option == JOptionPane.YES_OPTION) {
			System.exit(0);
		}
	}
	
		
	private void genpk() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, KeyStoreException, CertificateException, IOException, UnrecoverableEntryException{
		File f = new File(getkeypath("PublicKey", param));
		if(!f.exists()) {   
			File ks = returnkeystore();
			if (!ks.exists()){
				ks.mkdirs();
			}
			KeyPairGenerator kpg;
			kpg = KeyPairGenerator.getInstance("EC");
			ECGenParameterSpec ecsp;
			ecsp = new ECGenParameterSpec(param);
			kpg.initialize(ecsp);				
    	    KeyPair myKeyPair = kpg.generateKeyPair();                
			PublicKey pubKeyU = myKeyPair.getPublic();
			PrivateKey privKeyU = myKeyPair.getPrivate();
			byte[] b = pubKeyU.getEncoded();
			byte[] c = privKeyU.getEncoded();		
			String p = getkeypath("PublicKey",param);
			String q = getkeypath("PrivateKey",param);
			writefile(p, b);
			writefile(q, c);	
			textInput.setText("Key Pair generated at: "+ returnkeystore());		
		}else{
			showpop("PK Generation not performed: KeyPair already in KeyStore","PKCertificate Generator");
		}

	}
	
	private String readmsg (String pathmsg, String pathkey) throws Exception{
		
		byte[] msg = readtobyte(pathmsg);		
		byte[] pkV = readtobyte(pathkey);
		byte[] kU = readtobyte(getkeypath("PrivateKey",param));

		// A KeyFactory is used to convert encoded keys to their actual Java classes
        //KeyFactory ecKeyFac = KeyFactory.getInstance("EC", "BC");
		KeyFactory ecKeyFac = KeyFactory.getInstance("EC");
		
        // Recreate private key U
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(kU);
        PrivateKey privU = ecKeyFac.generatePrivate(pkcs8EncodedKeySpec);

		// Recreate public key V
        X509EncodedKeySpec x509EncodedKeySpecV = new X509EncodedKeySpec(pkV);
        PublicKey pubV = ecKeyFac.generatePublic(x509EncodedKeySpecV);

		//KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH", "BC");
		KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
 		ecdhU.init(privU);
 		ecdhU.doPhase(pubV,true);
		byte[] sk = ecdhU.generateSecret();

		SecretKey aesk = getAESKeyFromECDH(null,sk);
		String decryptedText = decryptWithPrefixIV(msg, aesk);

        return decryptedText;
	}
	private void writemsg (String title, String pathkey, String msg) throws Exception{				
		byte[] pkV = readtobyte(pathkey);
		byte[] kU = readtobyte(getkeypath("PrivateKey",param));

		// A KeyFactory is used to convert encoded keys to their actual Java classes
		KeyFactory ecKeyFac = KeyFactory.getInstance("EC");
		
        // Recreate private key U
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(kU);
        PrivateKey privU = ecKeyFac.generatePrivate(pkcs8EncodedKeySpec);

		// Recreate public key V
        X509EncodedKeySpec x509EncodedKeySpecV = new X509EncodedKeySpec(pkV);
        PublicKey pubV = ecKeyFac.generatePublic(x509EncodedKeySpecV);

		KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
 		ecdhU.init(privU);
 		ecdhU.doPhase(pubV,true);
		byte[] sk = ecdhU.generateSecret();

		byte[] a = msg.getBytes(StandardCharsets.UTF_8);

		SecretKey aesk = getAESKeyFromECDH(null,sk);
		byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
		byte[] encryptedText = encryptWithPrefixIV(a, aesk, iv);
		
		writefile(returnfilepath(title),encryptedText);
	}
	public static SecretKey getAESKeyFromECDH(char[] password, byte[] salt) 
	throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // iterationCount = 65536
        // keyLength = 256
        KeySpec spec = new PBEKeySpec(null, salt, 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;

    }
	 // AES-GCM needs GCMParameterSpec
	 public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] encryptedText = cipher.doFinal(pText);
        return encryptedText;

    }
	// prefix IV length + IV bytes to cipher text
    public static byte[] encryptWithPrefixIV(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

        byte[] cipherText = encrypt(pText, secret, iv);

        byte[] cipherTextWithIv = ByteBuffer.allocate(iv.length + cipherText.length)
                .put(iv)
                .put(cipherText)
                .array();
        return cipherTextWithIv;

    }
	public static String decrypt(byte[] cText, SecretKey secret, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cipher.doFinal(cText);
        return new String(plainText, StandardCharsets.UTF_8);

    }
	public static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static String decryptWithPrefixIV(byte[] cText, SecretKey secret) throws Exception {

        ByteBuffer bb = ByteBuffer.wrap(cText);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);
        //bb.get(iv, 0, iv.length);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        String plainText = decrypt(cipherText, secret, iv);
        return plainText;

    }
	// Utils
	public void writefile(String filepath, String input) throws IOException {
        File file = new File(filepath);
        PrintWriter out = new PrintWriter(file);
        out.println(input);
		out.flush();
		out.close();     
    }
	public void writefile(String filepath, byte[] input) throws IOException {        
        try (FileOutputStream outputStream = new FileOutputStream(filepath)) {
    			outputStream.write(input);
		};     
    }
	public byte[] readtobyte(String input) throws IOException{
		Path path = Paths.get(input);
		byte[] data = Files.readAllBytes(path);

		return data;
	}	
	public String getkeypath(String keyType, String param){
		String username = System.getProperty("user.name");
        String path = "C:\\Users\\"+ username + "\\Documents\\ECCMSG\\KeyStore";
        File file = new File(path + "\\" + keyType + "_" + param + ".txt");
        return file.toString();
    }
	public String returnfilepath(String fileName){
		String username = System.getProperty("user.name");
        String path = "C:\\Users\\"+ username + "\\Documents\\ECCMSG";
        File file = new File(path + "\\" + fileName + ".txt");
        return file.toString();
    }	
	public File returnkeystore(){
		String username = System.getProperty("user.name");
        String path = "C:\\Users\\"+ username + "\\Documents\\ECCMSG\\KeyStore";        
        return new File(path);
    }
	
	//Pop Ups
	
	private void showError(String error) {
		Object [] options = { "Accept" };
		JOptionPane.showOptionDialog(this, error, "Error",
				JOptionPane.DEFAULT_OPTION, JOptionPane.ERROR_MESSAGE, null, 
				options, options[0]);
	}
	private void showpop(String msg, String title) {
		Object [] options = { "Accept" };
		JOptionPane.showOptionDialog(this, msg, title,
				JOptionPane.DEFAULT_OPTION, JOptionPane.DEFAULT_OPTION, null, 
				options, options[0]);
	}
}
 
