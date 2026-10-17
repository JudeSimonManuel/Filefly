import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.RoundRectangle2D;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;

// ==========================================
// 1. LOGIC 
// ==========================================

class LanScanner {
    public static List<String> getHostsWithOpenPort(int port) {
        // 800ms guarantees the connection will succeed if the device exists, completely avoiding ARP drops.
        int timeoutMs = 800; 
        Set<String> openHosts = ConcurrentHashMap.newKeySet();
        List<String> targetIps = new ArrayList<>();

        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                
                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) continue;

                // Ignore fake virtual adapters (VMware, VirtualBox, WSL) that hijack the scan
                String name = ni.getDisplayName().toLowerCase();
                if (name.contains("virtual") || name.contains("wsl") || name.contains("vmware") || name.contains("vbox")) {
                    continue;
                }

                for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    InetAddress addr = ia.getAddress();
                    
                    if (addr instanceof Inet4Address && addr.isSiteLocalAddress()) {
                        byte[] ipBytes = addr.getAddress();
                        int ipInt = ((ipBytes[0] & 0xFF) << 24) | ((ipBytes[1] & 0xFF) << 16) |
                                ((ipBytes[2] & 0xFF) << 8) | (ipBytes[3] & 0xFF);

                        int prefixLength = ia.getNetworkPrefixLength();
                        // Prevent scanning massive subnets which would break the 4-second rule
                        if (prefixLength < 22) prefixLength = 24; 

                        int mask = 0xffffffff << (32 - prefixLength);
                        int networkAddr = ipInt & mask;
                        int broadcastAddr = networkAddr | ~mask;

                        // Pre-calculate all IPs to scan
                        for (int i = networkAddr + 1; i < broadcastAddr; i++) {
                            String targetIp = ((i >> 24) & 0xFF) + "." + ((i >> 16) & 0xFF) + "." +
                                    ((i >> 8) & 0xFF) + "." + (i & 0xFF);
                            if (!targetIp.equals(addr.getHostAddress())) {
                                targetIps.add(targetIp);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Scanner interface error: " + e.getMessage());
        }

        // Thread pool of 150 ensures we complete ~254 IPs in less than 2 seconds total.
        ExecutorService executor = Executors.newFixedThreadPool(150);
        
        for (String targetIp : targetIps) {
            executor.submit(() -> {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(targetIp, port), timeoutMs);
                    openHosts.add(targetIp);
                } catch (Exception ignored) {}
            });
        }

        executor.shutdown();
        try {
            // Strictly enforce the 4.5-second maximum time limit for the scanner
            executor.awaitTermination(4500, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return new ArrayList<>(openHosts);
    }
}

class ShortIPFinder {
    public static String getPrivateIP() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) continue;
                
                // Prioritize real physical Wi-Fi/Ethernet adapters for display
                String name = ni.getDisplayName().toLowerCase();
                if (name.contains("virtual") || name.contains("wsl") || name.contains("vmware") || name.contains("vbox")) {
                    continue;
                }

                for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                    if (addr instanceof Inet4Address && addr.isSiteLocalAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {}
        return "127.0.0.1";
    }
}

class sender {
    sender(String ip, int port, File[] files) {
        for (File f : files) {
            if (!f.exists()) {
                System.out.println("File does not exist: " + f.getName());
                continue;
            }
            try (Socket s = new Socket(ip, port);
                 BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f))) {

                DataOutputStream dos = new DataOutputStream(s.getOutputStream());
                System.out.println("Connected to " + ip + ":" + port + ". Sending: " + f.getName());

                dos.writeUTF(f.getName());
                dos.writeLong(f.length());
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = bis.read(buffer)) != -1) {
                    dos.write(buffer, 0, bytesRead);
                }
                dos.flush();
                System.out.println("File sent: " + f.getName());
            } catch (UnknownHostException u) {
                System.out.println("Unknown host: " + u.getMessage());
            } catch (IOException i) {
                System.out.println("Connection error: " + i.getMessage()); 
            }
        }
        System.out.println("All transfers completed.");
    }
}

class receiver implements Runnable {
    private String saveDirectory;
    private int port;
    private volatile boolean running = true;
    private ServerSocket serverSocket;

    receiver(String saveDirectory, int port) {
        this.saveDirectory = saveDirectory;
        this.port = port;
    }

    public void stopServer() {
        running = false;
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                System.out.println("Error closing server: " + e.getMessage());
            }
        }
    }

    @Override
    public void run() {
        try {
            serverSocket = new ServerSocket(port);
            System.out.println("My ip: " + ShortIPFinder.getPrivateIP() + " | Port: " + port);
            System.out.println("Waiting for client... Saving files to: " + saveDirectory);

            while (running) {
                try (Socket cs = serverSocket.accept();
                     DataInputStream dis = new DataInputStream(cs.getInputStream())) {

                    String filename = dis.readUTF();
                    System.out.println("connected");

                    String destination = saveDirectory + File.separator + filename;
                    File f = new File(destination);

                    if (f.exists()) {
                        final int[] choice = new int[1];
                        try {
                            SwingUtilities.invokeAndWait(() -> {
                                Object[] options = {"Replace", "Save Anyway"};
                                choice[0] = JOptionPane.showOptionDialog(null,
                                        "A file named '" + filename + "' already exists. What would you like to do?",
                                        "File Conflict",
                                        JOptionPane.YES_NO_OPTION,
                                        JOptionPane.WARNING_MESSAGE,
                                        null,
                                        options,
                                        options[1]);
                            });
                        } catch (Exception e) {
                            choice[0] = 1;
                        }

                        if (choice[0] == 1) {
                            String name = filename;
                            String ext = "";
                            int dotIndex = filename.lastIndexOf(".");
                            
                            if (dotIndex > 0) {
                                name = filename.substring(0, dotIndex);
                                ext = filename.substring(dotIndex);
                            }
                            
                            int count = 1;
                            while (f.exists()) {
                                destination = saveDirectory + File.separator + name + " (" + count + ")" + ext;
                                f = new File(destination);
                                count++;
                            }
                        }
                    }

                    System.out.println("Saving file to: " + destination);

                    try (BufferedOutputStream file = new BufferedOutputStream(new FileOutputStream(f))) {
                        byte[] buffer = new byte[4096];
                        int bytes;
                        long remaining = dis.readLong();
                        while (remaining > 0 && (bytes = dis.read(buffer, 0, (int) Math.min(buffer.length, remaining))) != -1) {
                            file.write(buffer, 0, bytes);
                            remaining -= bytes;
                        }
                        file.flush();
                        System.out.println("File downloaded successfully.\n");
                    }
                } catch (EOFException e) {
                    // Fails silently now
                } catch (SocketException e) {
                    if (!running) {
                        System.out.println("Server stopped gracefully.");
                        break;
                    } else {
                        System.out.println("Socket error: " + e.getMessage());
                    }
                } catch (Exception i) {
                    System.out.println("Transfer error: " + i.getMessage());
                }
            }
        } catch (BindException b) {
            System.out.println("Port " + port + " is already in use. Please select a different port or restart the app.");
        } catch (Exception i) {
            System.out.println("Server error: " + i.getMessage());
        }
    }
}

// ==========================================
// 2. MODERN UI 
// ==========================================


public class Linkin extends JFrame {

public class Filefly extends JFrame {


    private final CardLayout cardLayout = new CardLayout();
    private final JPanel mainPanel = new JPanel(cardLayout);

    private JPanel hostListPanel;
    private JTextArea logArea;
    private JTextField portInput;
    private int activePort = 8080; 
    
    private receiver currentReceiver;

    private final Color BG_COLOR = new Color(248, 250, 252);
    private final Color TEXT_DARK = new Color(15, 23, 42);
    private final Color TEXT_MUTED = new Color(100, 116, 139);
    private final Color PRIMARY_BTN = new Color(99, 102, 241);
    private final Color SUCCESS_BTN = new Color(16, 185, 129);
    private final Color SECONDARY_BTN = new Color(226, 232, 240);
    private final Color CARD_BG = new Color(255, 255, 255);


    public Linkin() {
        setTitle("Linkin - Fast Transfers");

    public Filefly() {
        setTitle("Filefly - Fast Transfers");

        setSize(520, 600);
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE); 
        setLocationRelativeTo(null);
        getContentPane().setBackground(BG_COLOR);

        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent windowEvent) {
                if (currentReceiver != null) {
                    currentReceiver.stopServer();
                }
                System.exit(0);
            }
        });

        setupLogConsole();

        mainPanel.add(createMainMenu(), "MENU");
        mainPanel.add(createSendMenu(), "SEND");
        mainPanel.add(createLogScreen(), "LOG");

        add(mainPanel);
    }

    private void setupLogConsole() {
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 14));
        logArea.setBackground(TEXT_DARK);
        logArea.setForeground(new Color(241, 245, 249));
        logArea.setMargin(new Insets(15, 15, 15, 15));
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);

        PrintStream printStream = new PrintStream(new OutputStream() {
            @Override
            public void write(int b) {
                SwingUtilities.invokeLater(() -> {
                    logArea.append(String.valueOf((char) b));
                    logArea.setCaretPosition(logArea.getDocument().getLength());
                });
            }
        });
        System.setOut(printStream);
        System.setErr(printStream);
    }

    private JPanel createMainMenu() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(BG_COLOR);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 0; gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel iconLabel = new JLabel("🚀", SwingConstants.CENTER);
        iconLabel.setFont(new Font("Segoe UI", Font.PLAIN, 55));


        JLabel title = new JLabel("Linkin", SwingConstants.CENTER);

        JLabel title = new JLabel("Filefly", SwingConstants.CENTER);

        title.setFont(new Font("Segoe UI", Font.BOLD, 38));
        title.setForeground(TEXT_DARK);

        JLabel subtitle = new JLabel("Lightning fast LAN transfers", SwingConstants.CENTER);
        subtitle.setFont(new Font("Segoe UI", Font.PLAIN, 15));
        subtitle.setForeground(TEXT_MUTED);

        JPanel portPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        portPanel.setBackground(BG_COLOR);
        JLabel portLabel = new JLabel("Network Port:");
        portLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        portLabel.setForeground(TEXT_DARK);
        
        portInput = new JTextField("8080", 5);
        portInput.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        portInput.setHorizontalAlignment(JTextField.CENTER);
        portInput.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(new Color(203, 213, 225), 2, true),
            new EmptyBorder(5, 5, 5, 5)
        ));

        JLabel portTip = new JLabel("(Recommended: 8000 - 9000)");
        portTip.setFont(new Font("Segoe UI", Font.ITALIC, 12));
        portTip.setForeground(TEXT_MUTED);

        portPanel.add(portLabel);
        portPanel.add(portInput);
        portPanel.add(portTip);

        JButton btnSend = new RoundedButton("Send Files", PRIMARY_BTN, Color.WHITE);
        JButton btnReceive = new RoundedButton("Receive Files", SUCCESS_BTN, Color.WHITE);

        btnSend.addActionListener(e -> {
            if(validateAndSetPort()) {
                cardLayout.show(mainPanel, "SEND");
                startScanning();
            }
        });

        btnReceive.addActionListener(e -> {
            if(validateAndSetPort()) {
                JFileChooser chooser = new JFileChooser();
                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                chooser.setDialogTitle("Select Folder to Save Received Files");

                if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                    String saveDir = chooser.getSelectedFile().getAbsolutePath();
                    cardLayout.show(mainPanel, "LOG");
                    System.out.println("====== RECEIVER ACTIVE ======");

                    currentReceiver = new receiver(saveDir, activePort);
                    Thread thread = new Thread(currentReceiver);
                    thread.start();
                }
            }
        });

        gbc.gridy = 0; panel.add(iconLabel, gbc);
        gbc.gridy = 1; panel.add(title, gbc);
        gbc.insets = new Insets(0, 10, 25, 10);
        gbc.gridy = 2; panel.add(subtitle, gbc);
        
        gbc.insets = new Insets(10, 10, 20, 10);
        gbc.gridy = 3; panel.add(portPanel, gbc);
        
        gbc.insets = new Insets(8, 10, 8, 10);
        gbc.gridy = 4; panel.add(btnSend, gbc);
        gbc.gridy = 5; panel.add(btnReceive, gbc);
        
        return panel;
    }
    
    private boolean validateAndSetPort() {
        try {
            int parsedPort = Integer.parseInt(portInput.getText().trim());
            if (parsedPort < 1024 || parsedPort > 65535) {
                JOptionPane.showMessageDialog(this, "Port must be between 1024 and 65535.", "Invalid Port", JOptionPane.ERROR_MESSAGE);
                return false;
            }
            activePort = parsedPort;
            return true;
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Please enter a valid numeric port.", "Invalid Input", JOptionPane.ERROR_MESSAGE);
            return false;
        }
    }

    private JPanel createSendMenu() {
        JPanel panel = new JPanel(new BorderLayout(0, 15));
        panel.setBackground(BG_COLOR);
        panel.setBorder(new EmptyBorder(20, 25, 20, 25));

        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(BG_COLOR);
        JLabel title = new JLabel("Available Devices");
        title.setFont(new Font("Segoe UI", Font.BOLD, 22));
        title.setForeground(TEXT_DARK);
        headerPanel.add(title, BorderLayout.WEST);

        hostListPanel = new JPanel();
        hostListPanel.setLayout(new BoxLayout(hostListPanel, BoxLayout.Y_AXIS));
        hostListPanel.setBackground(BG_COLOR);

        JScrollPane scrollPane = new JScrollPane(hostListPanel);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.setBackground(BG_COLOR);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        panel.add(headerPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        JButton btnBack = new RoundedButton("Back to Menu", SECONDARY_BTN, TEXT_DARK);
        btnBack.addActionListener(e -> cardLayout.show(mainPanel, "MENU"));
        panel.add(btnBack, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createLogScreen() {
        JPanel panel = new JPanel(new BorderLayout(0, 15));
        panel.setBackground(BG_COLOR);
        panel.setBorder(new EmptyBorder(20, 25, 20, 25));

        JLabel title = new JLabel("Transfer Activity");
        title.setFont(new Font("Segoe UI", Font.BOLD, 22));
        title.setForeground(TEXT_DARK);
        panel.add(title, BorderLayout.NORTH);

        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(new LineBorder(new Color(226, 232, 240), 1, true));
        panel.add(scrollPane, BorderLayout.CENTER);

        JButton btnBack = new RoundedButton("Back to Menu", SECONDARY_BTN, TEXT_DARK);
        btnBack.addActionListener(e -> {
            if (currentReceiver != null) {
                currentReceiver.stopServer();
                currentReceiver = null;
            }
            cardLayout.show(mainPanel, "MENU");
        });
        panel.add(btnBack, BorderLayout.SOUTH);

        return panel;
    }

    private void startScanning() {
        hostListPanel.removeAll();

        JLabel scanningLabel = new JLabel("Scanning network on port " + activePort + "...", SwingConstants.CENTER);
        scanningLabel.setFont(new Font("Segoe UI", Font.ITALIC, 14));
        scanningLabel.setForeground(TEXT_MUTED);
        scanningLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        hostListPanel.add(Box.createVerticalStrut(50));
        hostListPanel.add(scanningLabel);

        hostListPanel.revalidate(); hostListPanel.repaint();

        new Thread(() -> {
            List<String> openDevices = LanScanner.getHostsWithOpenPort(activePort);

            SwingUtilities.invokeLater(() -> {
                hostListPanel.removeAll();
                if (openDevices.isEmpty()) {
                    JLabel noneLabel = new JLabel("No open devices found.");
                    noneLabel.setFont(new Font("Segoe UI", Font.PLAIN, 15));
                    noneLabel.setForeground(TEXT_MUTED);
                    hostListPanel.add(noneLabel);
                } else {
                    for (String ip : openDevices) {
                        JButton hostBtn = createHostCardButton(ip);
                        hostBtn.addActionListener(e -> selectFileAndSend(ip));
                        hostListPanel.add(hostBtn);
                        hostListPanel.add(Box.createRigidArea(new Dimension(0, 10)));
                    }
                }
                hostListPanel.revalidate(); hostListPanel.repaint();
            });
        }).start();
    }

    private void selectFileAndSend(String ip) {
        JFileChooser chooser = new JFileChooser();
        chooser.setMultiSelectionEnabled(true);

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File[] files = chooser.getSelectedFiles();
            if (files.length == 0) return;

            cardLayout.show(mainPanel, "LOG");
            System.out.println("====== SENDER ACTIVE ======");
            System.out.println("Target IP: " + ip + " | Port: " + activePort);
            System.out.println("Queued " + files.length + " file(s) for transfer.");

            Thread thread = new Thread(() -> new sender(ip, activePort, files));
            thread.start();
        }
    }

    private JButton createHostCardButton(String ip) {
        JButton btn = new RoundedButton("🖥️  " + ip, CARD_BG, PRIMARY_BTN);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 16));
        btn.setHorizontalAlignment(SwingConstants.LEFT);
        btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 55));
        
        btn.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(226, 232, 240), 1, true),
                new EmptyBorder(15, 20, 15, 20)
        ));
        
        btn.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) {
                btn.setBackground(new Color(241, 245, 249));
            }
            public void mouseExited(MouseEvent e) {
                btn.setBackground(CARD_BG);
            }
        });
        return btn;
    }

    class RoundedButton extends JButton {
        private final Color bgColor;

        public RoundedButton(String text, Color bgColor, Color fgColor) {
            super(text);
            this.bgColor = bgColor;
            setForeground(fgColor);
            setFocusPainted(false);
            setContentAreaFilled(false);
            setBorderPainted(false);
            setCursor(new Cursor(Cursor.HAND_CURSOR));
            setFont(new Font("Segoe UI", Font.BOLD, 15));
            setPreferredSize(new Dimension(220, 48));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            
            g2.setColor(getModel().isRollover() ? bgColor.darker() : bgColor);
            g2.fill(new RoundRectangle2D.Float(0, 0, getWidth(), getHeight(), 15, 15));
            
            super.paintComponent(g);
            g2.dispose();
        }
    }

    public static void main(String[] args) {
        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (Exception ignored) {}


        SwingUtilities.invokeLater(() -> new Linkin().setVisible(true));

        SwingUtilities.invokeLater(() -> new Filefly().setVisible(true));

    }
}
