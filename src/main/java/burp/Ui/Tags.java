package burp.Ui;

import burp.Bootstrap.YamlReader;
import burp.IBurpExtenderCallbacks;
import burp.ITab;

import javax.swing.*;
import java.awt.*;

public class Tags implements ITab {
    private final JTabbedPane tabs;

    private String Name;

    private BaseSettingsTag baseSettingsTag;
    private ScanQueueTag scanQueueTag;

    private YamlReader yamlReader;

    public Tags(IBurpExtenderCallbacks callbacks, String name) {
        this.tabs = new JTabbedPane();

        this.Name = name;

        this.yamlReader = YamlReader.getInstance(callbacks);

        //扫描队列窗口
        this.scanQueueTag = new ScanQueueTag(callbacks, tabs);

        //基本设置窗口
        this.baseSettingsTag = new BaseSettingsTag(callbacks, tabs, yamlReader);

        //自定义界面导入
        callbacks.customizeUiComponent(tabs);

        //将自定义选项卡添加到burp的UI中
        callbacks.addSuiteTab(Tags.this);
    }


    @Override
    public String getTabCaption() {
        return this.Name;
    }

    @Override
    public Component getUiComponent() {
        return this.tabs;
    }

    public BaseSettingsTag getBaseSettingsTag() {
        return baseSettingsTag;
    }

    public ScanQueueTag getScanQueueTag() {
        return scanQueueTag;
    }
}
