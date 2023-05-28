package ui.component;

import javax.swing.*;
import java.awt.*;

public class ScanOptionsTipsDialog extends JDialog {
    JTextPane textPane;

    JButton closeBtn;

    public ScanOptionsTipsDialog(String text) {
        setLayout(new BorderLayout());
        setTitle("扫描参数帮助");

        textPane = new JTextPane();
        textPane.setContentType("text/html; charset=UTF-8");
        textPane.setText(text);

        textPane.setEditable(false);

        add(new JScrollPane(textPane), BorderLayout.CENTER);

        closeBtn = new JButton("关闭");

        closeBtn.addActionListener(e -> dispose());

        JPanel southPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        southPanel.add(closeBtn);

        add(southPanel, BorderLayout.SOUTH);

        pack();
        setSize(getPreferredSize());
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
    }
}
