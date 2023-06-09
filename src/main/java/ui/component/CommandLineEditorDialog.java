package ui.component;

import entities.OptionsCommandLine;
import models.CommandLineTableModel;

import javax.swing.*;
import java.awt.*;

import static utils.GlobalStaticVariables.EX_MSG;

public class CommandLineEditorDialog extends JDialog {
    OptionsCommandLine optionsCommandLine;
    CommandLineTableModel commandLineTableModel;
    int id;
    Boolean enableEdit;

    JPanel tagPanel;
    JLabel tagLabel;
    JTextField tagTextField;

    JPanel commandLinePanel;
    JLabel commandLineLabel;
    JTextField commandLineTextField;

    JPanel buttonPanel;
    JButton okBtn;
    JButton cancelBtn;

    public CommandLineEditorDialog(CommandLineTableModel commandLineTableModel, int id, Boolean enableEdit) {
        this.commandLineTableModel = commandLineTableModel;
        this.id = id;
        optionsCommandLine = commandLineTableModel.getOptionsCommandLineById(id);
        this.enableEdit = enableEdit;
        setLayout(new BorderLayout());

        if (enableEdit) {
            setTitle(EX_MSG.getMsg("commandLineEdit"));
        } else {
            setTitle(EX_MSG.getMsg("commandLineDetail"));
        }

        tagPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        tagLabel = new JLabel(EX_MSG.getMsg("tag"));
        tagTextField = new JTextField(optionsCommandLine.getTag());
        tagTextField.setEnabled(enableEdit);

        tagPanel.add(tagLabel);
        tagPanel.add(tagTextField);

        add(tagPanel, BorderLayout.NORTH);

        commandLinePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        commandLineLabel = new JLabel(EX_MSG.getMsg("commandLine"));
        commandLineTextField = new JTextField(optionsCommandLine.getCommandLineStr(), 128);
        commandLineTextField.setEnabled(enableEdit);

        commandLinePanel.add(commandLineLabel);
        commandLinePanel.add(commandLineTextField);

        add(commandLinePanel, BorderLayout.CENTER);

        buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        okBtn = new JButton(EX_MSG.getMsg("ok"));
        okBtn.setEnabled(enableEdit);

        if (enableEdit) {
            cancelBtn = new JButton(EX_MSG.getMsg("cancel"));
        } else {
            cancelBtn = new JButton(EX_MSG.getMsg("close"));
        }

        buttonPanel.add(okBtn);
        buttonPanel.add(cancelBtn);

        add(buttonPanel, BorderLayout.SOUTH);


        pack();
        setSize(getPreferredSize());
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        buttonEventListeningInit();
    }

    private void buttonEventListeningInit() {
        okBtn.addActionListener(e -> {
            String tagStr = tagTextField.getText();
            String commandLineStr = commandLineTextField.getText();

            if (null == tagStr || tagStr.trim().isEmpty() || null == commandLineStr || commandLineStr.trim().isEmpty()) {
                dispose();
                return;
            }

            tagStr = tagStr.trim();
            commandLineStr = commandLineStr.trim();

            commandLineTableModel.updateTagById(id, tagStr);
            commandLineTableModel.updateCommandLinesById(id, commandLineStr);

            dispose();
        });

        cancelBtn.addActionListener(e -> {
            dispose();
        });
    }
}
