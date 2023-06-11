package ui.panel.subPanel;

import burp.BurpExtender;
import entities.CommandLineColumnName;
import entities.InjectionStatus;
import entities.ScanTaskColumnName;
import entities.ScanTaskStatus;
import utils.MessageUtil;

import javax.swing.*;
import java.awt.*;
import java.util.Locale;

import static utils.MessageUtil.inChinese;

public class GlobalConfigPanel extends JPanel {
    JPanel languageChooserPanel;
    JLabel label;
    ButtonGroup buttonGroup;
    JRadioButton chineseRadioButton;
    JRadioButton englishRadioButton;

    //    Locale currentLocale;
    MessageUtil messageUtil;

    // other config panel


    public GlobalConfigPanel() {
        setLayout(new BorderLayout());
        messageUtil = new MessageUtil();


        languageChooserPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        label = new JLabel(messageUtil.getMsg("language"));

        buttonGroup = new ButtonGroup();
        chineseRadioButton = new JRadioButton(messageUtil.getMsg("chinese"));
        englishRadioButton = new JRadioButton(messageUtil.getMsg("english"));
        buttonGroup.add(chineseRadioButton);
        buttonGroup.add(englishRadioButton);

        if (inChinese()) {
            chineseRadioButton.setSelected(true);
        } else {
            englishRadioButton.setSelected(true);
        }


        languageChooserPanel.add(label);
        languageChooserPanel.add(chineseRadioButton);
        languageChooserPanel.add(englishRadioButton);

        add(languageChooserPanel, BorderLayout.NORTH);

        initRadioButtonActionListen();
    }

    private void initRadioButtonActionListen() {
        chineseRadioButton.addActionListener(e -> {
            if (chineseRadioButton.isSelected()) {
                Locale preLocale = messageUtil.getLocale();
//                BurpExtender.stdout.println(String.format("---->60, local: %s", preLocale.toString()));
                if (!inChinese(preLocale)) {
//                    BurpExtender.stdout.println("---->62");
//                    messageUtil.setLocale(Locale.SIMPLIFIED_CHINESE);
                    updateI18n(Locale.SIMPLIFIED_CHINESE);
                }
            }
        });

        englishRadioButton.addActionListener(e -> {
            if (englishRadioButton.isSelected()) {
                Locale preLocale = messageUtil.getLocale();
                if (inChinese(preLocale)) {
//                    messageUtil.setLocale(Locale.US);
                    updateI18n(Locale.US);
                }
            }
        });
    }

    private void updateMySelfI18n() {
        label.setText(messageUtil.getMsg("language"));
        chineseRadioButton.setText(messageUtil.getMsg("chinese"));
        englishRadioButton.setText(messageUtil.getMsg("english"));
    }

    public void updateI18n(Locale locale) {
        messageUtil = new MessageUtil(locale);
        updateMySelfI18n();
        ScanTaskStatus.updateI18n();
        InjectionStatus.updateI18n();
        CommandLineColumnName.updateI18n();
        ScanTaskColumnName.updateI18n();

        BurpExtender.updateI18n(messageUtil);

    }
}
