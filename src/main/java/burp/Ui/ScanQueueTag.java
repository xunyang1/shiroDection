package burp.Ui;

import burp.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class ScanQueueTag extends AbstractTableModel implements IMessageEditorController {
    private JSplitPane mjSplitPane;
    private ResTable resTable;
    private JScrollPane resPanel;
    private JSplitPane detailPanel;
    private  JTabbedPane LTable;
    private  JTabbedPane RTable;
    private IMessageEditor LRequestTextEditor;
    private IMessageEditor RRequestTextEditor;

    private List<ScanQueueTag.TablesData> ResData = new ArrayList<ScanQueueTag.TablesData>();
    private IHttpRequestResponse currentlyDisplayedItem;

    public ScanQueueTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs) {
        JPanel scanQueue = new JPanel(new BorderLayout());

        //设置主面板，垂直分割
        mjSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        //接下来实现两个子面板，嵌入mjSplitPane上下
        //结果显示面板(一个可滑动的表格组件)
        resTable = new ResTable(ScanQueueTag.this);
        resPanel = new JScrollPane(resTable);

        //请求与响应显示面板(水平分割面板)
        detailPanel = new JSplitPane();//默认是水平分割
        detailPanel.setResizeWeight(0.5);

        //请求面板(选项卡面板)
        LTable = new JTabbedPane();
        LRequestTextEditor = callbacks.createMessageEditor(ScanQueueTag.this, false);
        LTable.addTab("Request", LRequestTextEditor.getComponent());

        //响应面板(选项卡面板)
        RTable = new JTabbedPane();
        RRequestTextEditor = callbacks.createMessageEditor(ScanQueueTag.this, false);
        RTable.addTab("Response", RRequestTextEditor.getComponent());

        //将请求面板与响应面板加入到请求与响应显示面板
        detailPanel.add(LTable, "left");
        detailPanel.add(RTable, "right");

        //将结果显示面板和请求与响应显示面板添加到主面板
        mjSplitPane.add(resPanel, "left");
        mjSplitPane.add(detailPanel, "right");

        //这个spiltPanel设计完毕，添加到Jpanel中
        scanQueue.add(mjSplitPane);

        //将Jpanel添加到tabs中做为一个选项卡
        tabs.addTab("扫描队列", scanQueue);
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public int getRowCount() {
        return this.ResData.size();
    }

    @Override
    public int getColumnCount() {
        return 9;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        TablesData datas = this.ResData.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return datas.id;
            case 1:
                return datas.extensionMethod;
            case 2:
                return datas.encryptMethod;
            case 3:
                return datas.requestMethod;
            case 4:
                return datas.url;
            case 5:
                return datas.statusCode;
            case 6:
                return datas.issue;
            case 7:
                return datas.startTime;
            case 8:
                return datas.endTime;
        }
        return null;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "id";
            case 1:
                return "extensionMethod";
            case 2:
                return "encryptMethod";
            case 3:
                return "requestMethod";
            case 4:
                return "url";
            case 5:
                return "statusCode";
            case 6:
                return "issue";
            case 7:
                return "startTime";
            case 8:
                return "endTime";
        }
        return null;
    }

    /**
     * 表格添加功能
     * @param extensionMethod
     * @param encryptMethod
     * @param requestMethod
     * @param url
     * @param statusCode
     * @param issue
     * @param requestResponse
     * @return
     */
    public int add(String extensionMethod, String encryptMethod, String requestMethod,
                   String url, String statusCode, String issue,
                   IHttpRequestResponse requestResponse){
        synchronized (ResData){
            Date date = new Date();
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String startTime = simpleDateFormat.format(date);

            int id = this.ResData.size();
            this.ResData.add(
                    new TablesData(
                            id,
                            extensionMethod,
                            encryptMethod,
                            requestMethod,
                            url,
                            statusCode,
                            issue,
                            startTime,
                            "",
                            requestResponse
                    )
            );
            fireTableRowsInserted(id, id);
            return id;
        }
    }

    /**
     * 更新任务状态
     * @param id
     * @param extensionMethod
     * @param encryptMethod
     * @param requestMethod
     * @param url
     * @param statusCode
     * @param issue
     * @param requestResponse
     * @return
     */
    public int save(int id, String extensionMethod, String encryptMethod, String requestMethod,
                   String url, String statusCode, String issue,
                   IHttpRequestResponse requestResponse){
        ScanQueueTag.TablesData dataEntry = ScanQueueTag.this.ResData.get(id);
        String startTime = dataEntry.startTime;

        Date d = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String endTime = sdf.format(d);

        synchronized (this.ResData) {
            this.ResData.set(
                    id,
                    new TablesData(
                            id,
                            extensionMethod,
                            encryptMethod,
                            requestMethod,
                            url,
                            statusCode,
                            issue,
                            startTime,
                            endTime,
                            requestResponse
                    )
            );
            fireTableRowsUpdated(id, id);
            return id;
        }
    }

    //创建自定义表格组件
    private class ResTable extends JTable{
        public ResTable(TableModel tableModel){
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            TablesData tablesData = ScanQueueTag.this.ResData.get(convertRowIndexToModel(row));
            LRequestTextEditor.setMessage(tablesData.requestResponse.getRequest(), true);
            RRequestTextEditor.setMessage(tablesData.requestResponse.getResponse(), true);
            currentlyDisplayedItem = tablesData.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }

    }

    //界面显示数据存储模块
    private static class TablesData {
        final int id;
        final String extensionMethod;
        final String encryptMethod;
        final String requestMethod;
        final String url;
        final String statusCode;
        final String issue;
        final String startTime;
        final String endTime;
        final IHttpRequestResponse requestResponse;

        public TablesData(int id, String extensionMethod, String encryptMethod,
                          String requestMethod, String url, String statusCode,
                          String issue, String startTime, String endTime,
                          IHttpRequestResponse requestResponse) {
            this.id = id;
            this.extensionMethod = extensionMethod;
            this.encryptMethod = encryptMethod;
            this.requestMethod = requestMethod;
            this.url = url;
            this.statusCode = statusCode;
            this.issue = issue;
            this.startTime = startTime;
            this.endTime = endTime;
            this.requestResponse = requestResponse;
        }
    }
}
