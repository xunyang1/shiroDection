package burp.Ui;

import burp.Bootstrap.CustomBurpHelpers;
import burp.Bootstrap.YamlReader;
import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

public class BaseSettingsTag {
    private YamlReader yamlReader;
    private IBurpExtenderCallbacks callbacks;
    private CustomBurpHelpers customBurpHelpers;

    private JCheckBox isStartBox1;
    private JCheckBox isStartBox2;

    private JTextArea area;
    private JScrollPane scroll;
    private JButton button1;

    public BaseSettingsTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs, YamlReader yamlReader) {
        JPanel jPanel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        this.yamlReader = yamlReader;
        this.callbacks = callbacks;

        input1_1(jPanel, c);
        input1_2(jPanel, c);

        input2_1(jPanel, c);
        input2_2(jPanel, c);

        input3_1(jPanel, c);
        input3_2(jPanel, c);
        input3_3(jPanel, c);

        tabs.addTab("基本设置", jPanel);
    }

    private void input1_1(JPanel jPanel, GridBagConstraints c){
        JLabel label1_1 = new JLabel("插件启动");
        label1_1.setForeground(new Color(255, 89, 18));
        label1_1.setFont(new Font("Serif", Font.PLAIN, label1_1.getFont().getSize()));
        c.insets = new Insets(5,5,5,5);
        //https://blog.csdn.net/qq_18989901/article/details/52403737
        c.gridx = 0;
        c.gridy = 0;
        jPanel.add(label1_1, c);
    }

    private void input1_2(JPanel jPanel, GridBagConstraints c){
        this.isStartBox1 = new JCheckBox("启动", this.yamlReader.getBoolean("isStart"));
        this.isStartBox1.setFont(new Font("Serif", Font.PLAIN, this.isStartBox1.getFont().getSize()));
        c.insets = new Insets(5,5,5,5);
        c.gridx = 0;
        c.gridy = 1;
        jPanel.add(this.isStartBox1, c);
    }

    private void input2_1(JPanel jPanel, GridBagConstraints c) {
        JLabel label1_1 = new JLabel("密钥探测扩展");
        label1_1.setForeground(new Color(255, 89, 18));
        label1_1.setFont(new Font("Serif", Font.PLAIN, label1_1.getFont().getSize()));
        c.insets = new Insets(5,5,5,5);
        //https://blog.csdn.net/qq_18989901/article/details/52403737
        c.gridx = 0;
        c.gridy = 2;
        jPanel.add(label1_1, c);
    }

    private void input2_2(JPanel jPanel, GridBagConstraints c) {
        this.isStartBox2 = new JCheckBox("启动", this.yamlReader.getBoolean("isStart"));
        this.isStartBox2.setFont(new Font("Serif", Font.PLAIN, this.isStartBox2.getFont().getSize()));
        c.insets = new Insets(5,5,5,5);
        c.gridx = 0;
        c.gridy = 3;
        jPanel.add(this.isStartBox2, c);
    }

    private void input3_1(JPanel jPanel, GridBagConstraints c) {
        JLabel label1_1 = new JLabel("密钥添加");
        label1_1.setForeground(new Color(255, 89, 18));
        label1_1.setFont(new Font("Serif", Font.PLAIN, label1_1.getFont().getSize()));
        c.insets = new Insets(5,5,5,5);
        //https://blog.csdn.net/qq_18989901/article/details/52403737
        c.gridx = 0;
        c.gridy = 4;
        jPanel.add(label1_1, c);
    }

    private void input3_2(JPanel jPanel, GridBagConstraints c) {
        this.area = new JTextArea(); // 创建一个多行输入框
        area.setEditable(true); // 设置输入框允许编辑
        area.setColumns(18); // 设置输入框的长度为14个字符
        area.setRows(24); // 设置输入框的高度为3行字符
        area.setLineWrap(true); // 设置每行是否折叠。为true的话，输入字符超过每行宽度就会自动换行
        this.scroll = new JScrollPane(area); // 创建一个滚动条
        c.insets = new Insets(5,5,5,5);
        c.gridwidth=1;
        c.gridheight=2;
        c.gridx = 0;
        c.gridy = 5;

        jPanel.add(this.scroll, c); // 在面板上添加滚动条
    }

    private void input3_3(JPanel jPanel, GridBagConstraints c) {
        this.button1 = new JButton("添加");
        this.button1.setFont(new Font("Serif", Font.PLAIN, this.button1.getFont().getSize()));

        c.insets = new Insets(5,5,5,5);
        c.gridx = 1;
        c.gridy = 5;

        button1.addActionListener((e) -> {
            onButton();
        });

        jPanel.add(this.button1, c);
    }

    private void onButton() {
        //获取文本框输入
        String text = area.getText();
        List<String> payloadsAdd = new ArrayList<>(Arrays.asList(text.split("[\\n]")));
        if (payloadsAdd.size() == 1 && payloadsAdd.get(0).equals("")){
            JOptionPane.showMessageDialog(null, "不能为空~.~");
            return;
        }

        //获取shiroKey.txt
        CustomBurpHelpers customBurpHelpers = new CustomBurpHelpers(callbacks);
        List<String> payloadsList = customBurpHelpers.getPayloadList();

        //判断是否重复，重复就删除
        try {
            for(Iterator<String> it = payloadsList.iterator(); it.hasNext();){
                String payload = it.next();
                if (payloadsList.contains(payload)){
                    payloadsAdd.remove(payload);
                }
            }
        }catch (Exception e){
            e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
            return;
        }


        //添加至配置文件
        if (customBurpHelpers.addPayloadList(payloadsAdd)){
            area.setText("");
            JOptionPane.showMessageDialog(null, "添加成功~");
        }else {
            JOptionPane.showMessageDialog(null, "添加失败:(");
        }
    }

    public Boolean isExtensionStart() {
        return this.isStartBox1.isSelected();
    }

    public Boolean isCipherKeyDetectionStart() {
        return this.isStartBox2.isSelected();
    }
}
