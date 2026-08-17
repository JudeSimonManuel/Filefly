import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;

// ==========================================
// 1. LOGIC (Updated for Custom Save Path)
// ==========================================

class LanScanner {
    public static List<String> getHostsWithOpenPort() {
        int port = 8080;
        int timeoutMs = 200;
        List<String> openHosts = new CopyOnWriteArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(200);

        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();

                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) {
                    continue;
                }

                boolean foundLan = false;
                for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    InetAddress addr = ia.getAddress();

                    if (addr instanceof Inet4Address && addr.isSiteLocalAddress()) {

                        byte[] ipBytes = addr.getAddress();
                        int ipInt = ((ipBytes[0] & 0xFF) << 24) | ((ipBytes[1] & 0xFF) << 16) |
                                ((ipBytes[2] & 0xFF) << 8) | (ipBytes[3] & 0xFF);

                        int mask = 0xffffffff << (32 - ia.getNetworkPrefixLength());
                        int networkAddr = ipInt & mask;
                        int broadcastAddr = networkAddr | ~mask;

                        for (int i = networkAddr + 1; i < broadcastAddr; i++) {
                            String targetIp = ((i >> 24) & 0xFF) + "." + ((i >> 16) & 0xFF) + "." +
                                    ((i >> 8) & 0xFF) + "." + (i & 0xFF);

                            executor.submit(() -> {
                                try (Socket socket = new Socket()) {
                                    socket.connect(new InetSocketAddress(targetIp, port), timeoutMs);
                                    openHosts.add(targetIp);
                                } catch (Exception ignored) {}
                            });
                        }
                        foundLan = true;
                        break;
                    }
                }
                if (foundLan) break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        executor.shutdown();
        try {
            executor.awaitTermination(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return new ArrayList<>(openHosts);
    }
}

class ShortIPFinder {
    public static String getPrivateIP() throws SocketException {
        return NetworkInterface.networkInterfaces()
                .filter(ni -> { try { return ni.isUp() && !ni.isLoopback(); } catch (Exception e) { return false; } })
                .flatMap(NetworkInterface::inetAddresses)
                .filter(addr -> !addr.isLoopbackAddress() && addr instanceof Inet4Address && addr.isSiteLocalAddress())
                .map(InetAddress::getHostAddress)
                .findFirst()
                .orElse("127.0.0.1");
    }
}

class sender {
    sender(String ip, File[] files) {
        for (File f : files) {
            if (!f.exists()) {
                System.out.println("File does not exist: " + f.getName());
                continue;
            }
            try (Socket s = new Socket(ip, 8080);
                 BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f))) {

                DataOutputStream dos = new DataOutputStream(s.getOutputStream());
                System.out.println("connected. Sending: " + f.getName());

                dos.writeUTF(f.getName());
                dos.writeLong(f.length());
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = bis.read(buffer)) != -1) {
                    dos.write(buffer, 0, bytesRead);
                }
                dos.flush();
                System.out.println("file sent: " + f.getName());
            } catch (UnknownHostException u) {
                u.printStackTrace();
            } catch (IOException i) {
                i.printStackTrace();
            }
        }
        System.out.println("All transfers completed.");
    }
}

class receiver {
    // UPDATED: Added saveDirectory parameter
    receiver(String saveDirectory) {
        try(ServerSocket ss = new ServerSocket(8080)){
            System.out.println("My ip:" + ShortIPFinder.getPrivateIP());
            System.out.println("Waiting for client... Saving files to: " + saveDirectory);

            while(true) {
                try (Socket cs = ss.accept();
                     DataInputStream dis = new DataInputStream(cs.getInputStream())) {

                    System.out.println("connected");
                    String filename = dis.readUTF();

                    // UPDATED: Dynamically construct the file path
                    String destination = saveDirectory + File.separator + filename;
                    System.out.println("Saving file to: " + destination);

                    File f = new File(destination);
                    try (BufferedOutputStream file = new BufferedOutputStream(new FileOutputStream(f))) {
                        byte[] buffer = new byte[4096];
                        int bytes;
                        long remaining = dis.readLong();
                        while (remaining > 0 && (bytes = dis.read(buffer, 0, (int) Math.min(buffer.length, remaining))) != -1) {
                            file.write(buffer, 0, bytes);
                            remaining -= bytes;
                        }
                        file.flush();
                        System.out.println("file downloaded successfully.");
                    }
                }
                catch (EOFException e) {
                    System.out.println("-> Ignored a port scan.");
                }
                catch (Exception i) {
                    i.printStackTrace();
                }
            }
        }
        catch (Exception i){
            i.printStackTrace();
        }
    }
}

// ==========================================
// 2. MODERN UI
// ==========================================

public class Filefly extends JFrame {

    private final CardLayout cardLayout = new CardLayout();
    private final JPanel mainPanel = new JPanel(cardLayout);

    private JPanel hostListPanel;
    private JTextArea logArea;

    private final Color BG_COLOR = new Color(248, 250, 252);
    private final Color TEXT_DARK = new Color(15, 23, 42);
    private final Color TEXT_MUTED = new Color(71, 85, 105);
    private final Color PRIMARY_BTN = new Color(79, 70, 229);
    private final Color SUCCESS_BTN = new Color(16, 185, 129);
    private final Color SECONDARY_BTN = new Color(203, 213, 225);
    private final Color CARD_BG = new Color(255, 255, 255);

    public Filefly() {
        setTitle("Filefly");
        setSize(500, 550);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        getContentPane().setBackground(BG_COLOR);

        setupLogConsole();

        mainPanel.add(createMainMenu(), "MENU");
        mainPanel.add(createSendMenu(), "SEND");
        mainPanel.add(createLogScreen(), "LOG");

        add(mainPanel);
    }

    private void setupLogConsole() {
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Segoe UI", Font.PLAIN, 15));
        logArea.setBackground(CARD_BG);
        logArea.setForeground(TEXT_MUTED);
        logArea.setMargin(new Insets(20, 20, 20, 20));
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
        gbc.insets = new Insets(12, 12, 12, 12);
        gbc.gridx = 0; gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel iconLabel = new JLabel("🚀", SwingConstants.CENTER);
        iconLabel.setFont(new Font("Segoe UI", Font.PLAIN, 48));

        JLabel title = new JLabel("Filefly", SwingConstants.CENTER);
        title.setFont(new Font("Segoe UI", Font.BOLD, 36));
        title.setForeground(TEXT_DARK);

        JLabel subtitle = new JLabel("Lightning fast LAN transfers", SwingConstants.CENTER);
        subtitle.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        subtitle.setForeground(TEXT_MUTED);

        JButton btnSend = createModernButton("Send Files", PRIMARY_BTN, Color.WHITE);
        JButton btnReceive = createModernButton("Receive Files", SUCCESS_BTN, Color.WHITE);

        btnSend.addActionListener(e -> {
            cardLayout.show(mainPanel, "SEND");
            startScanning();
        });

        // UPDATED: Prompts the user to select a directory before starting the receiver
        btnReceive.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setDialogTitle("Select Folder to Save Received Files");

            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                String saveDir = chooser.getSelectedFile().getAbsolutePath();
                cardLayout.show(mainPanel, "LOG");
                System.out.println("====== RECEIVER ACTIVE ======");

                Thread thread = new Thread(() -> new receiver(saveDir));
                thread.start();
            }
        });

        gbc.gridy = 0; panel.add(iconLabel, gbc);
        gbc.gridy = 1; panel.add(title, gbc);
        gbc.insets = new Insets(0, 12, 30, 12);
        gbc.gridy = 2; panel.add(subtitle, gbc);
        gbc.insets = new Insets(8, 12, 8, 12);
        gbc.gridy = 3; panel.add(btnSend, gbc);
        gbc.gridy = 4; panel.add(btnReceive, gbc);
        return panel;
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

        JButton btnBack = createModernButton("Back to Menu", SECONDARY_BTN, TEXT_DARK);
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

        JButton btnBack = createModernButton("Back to Menu", SECONDARY_BTN, TEXT_DARK);
        btnBack.addActionListener(e -> cardLayout.show(mainPanel, "MENU"));
        panel.add(btnBack, BorderLayout.SOUTH);

        return panel;
    }

    private void startScanning() {
        hostListPanel.removeAll();

        JLabel scanningLabel = new JLabel("Scanning network...", SwingConstants.CENTER);
        scanningLabel.setFont(new Font("Segoe UI", Font.ITALIC, 14));
        scanningLabel.setForeground(TEXT_MUTED);
        scanningLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        hostListPanel.add(Box.createVerticalStrut(50));
        hostListPanel.add(scanningLabel);

        hostListPanel.revalidate(); hostListPanel.repaint();

        new Thread(() -> {
            List<String> openDevices = LanScanner.getHostsWithOpenPort();

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
            System.out.println("Target IP: " + ip);
            System.out.println("Queued " + files.length + " file(s) for transfer.");

            Thread thread = new Thread(() -> new sender(ip, files));
            thread.start();
        }
    }

    private JButton createModernButton(String text, Color bg, Color fg) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 15));
        btn.setBackground(bg);
        btn.setForeground(fg);
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setPreferredSize(new Dimension(220, 48));

        btn.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) {
                btn.setBackground(bg.darker());
            }
            public void mouseExited(MouseEvent e) {
                btn.setBackground(bg);
            }
        });
        return btn;
    }

    private JButton createHostCardButton(String ip) {
        JButton btn = new JButton("🖥️  " + ip);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 16));
        btn.setBackground(CARD_BG);
        btn.setForeground(PRIMARY_BTN);
        btn.setFocusPainted(false);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
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

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {}

        SwingUtilities.invokeLater(() -> new Filefly().setVisible(true));
    }
}