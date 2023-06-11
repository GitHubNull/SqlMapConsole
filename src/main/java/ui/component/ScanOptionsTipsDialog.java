package ui.component;

import javax.swing.*;
import java.awt.*;

import static utils.GlobalStaticVariables.EX_MSG;

public class ScanOptionsTipsDialog extends JDialog {
    JTextPane textPane;

    JButton closeBtn;

    public ScanOptionsTipsDialog(String text) {
        setLayout(new BorderLayout());
        setTitle(EX_MSG.getMsg("commandLineHelp"));

        textPane = new JTextPane();
        textPane.setContentType("text/html; charset=UTF-8");
        textPane.setText(text);

        textPane.setEditable(false);

        add(new JScrollPane(textPane), BorderLayout.CENTER);

        closeBtn = new JButton(EX_MSG.getMsg("close"));

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
