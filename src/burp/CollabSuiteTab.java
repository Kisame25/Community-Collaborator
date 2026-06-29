package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import utils.Logger;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CollabSuiteTab extends JPanel {
    private final MontoyaApi api;
    private final InteractshSession clientWrapper;
    private final Logger logger;

    private final DefaultTableModel interactionTableModel;
    private final JTable interactionTable;
    private final TableRowSorter<DefaultTableModel> tableSorter;
    private final JTabbedPane detailTabs;
    private final JTextArea descArea;
    private final JTextArea requestArea;
    private final JTextArea responseArea;
    private final List<InteractionData> interactionList;
    private final JScrollPane descScroll;
    private final JScrollPane requestScroll;
    private final JScrollPane responseScroll;
    private final JPanel requestPanel;
    private final JPanel responsePanel;
    private final HttpRequestEditor httpReqEditor;
    private final HttpResponseEditor httpRespEditor;
    private final JSpinner countSpinner;
    private final JCheckBox includeServerCb;
    private final JLabel statusLabel;
    private final JTextField searchField;
    private final Map<String, JToggleButton> filterButtons;
    private final javax.swing.Timer searchTimer;

    private boolean isGenerating;
    private boolean isPolling;
    private int interactionCount;

    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MMM-dd HH:mm:ss.SSS z");
    private static final String[] COLUMNS = {"#", "Time", "Type", "Payload", "Source IP address", "Comment"};

    public CollabSuiteTab(MontoyaApi api, InteractshSession clientWrapper, Logger logger) {
        this.api = api;
        this.clientWrapper = clientWrapper;
        this.logger = logger;
        this.interactionList = new ArrayList<>();
        this.filterButtons = new HashMap<>();

        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 8, 10));

        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));

        toolbar.add(new JLabel("Payloads to generate:"));
        countSpinner = new JSpinner(new SpinnerNumberModel(1, 1, 100, 1));
        ((JSpinner.DefaultEditor) countSpinner.getEditor()).getTextField().setColumns(3);
        toolbar.add(countSpinner);

        JButton copyBtn = new JButton("Copy to clipboard");
        copyBtn.addActionListener(e -> generateAndCopy());
        toolbar.add(copyBtn);

        includeServerCb = new JCheckBox("Include server location");
        includeServerCb.setSelected(true);
        toolbar.add(includeServerCb);

        toolbar.add(new JSeparator(SwingConstants.VERTICAL));

        JButton pollNowBtn = new JButton("Poll now");
        pollNowBtn.addActionListener(e -> pollInteractions());
        toolbar.add(pollNowBtn);

        headerPanel.add(toolbar);

        JPanel filterBar = new JPanel(new BorderLayout(10, 4));
        filterBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UIManager.getColor("Separator.shadow")),
                new EmptyBorder(6, 4, 6, 4)));

        JPanel typeFilterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JLabel filterLabel = new JLabel("Filter:");
        filterLabel.setFont(filterLabel.getFont().deriveFont(Font.BOLD));
        typeFilterPanel.add(filterLabel);

        for (String type : new String[]{"DNS", "HTTP", "SMTP"}) {
            JToggleButton btn = new JToggleButton(type, false);
            btn.setFont(btn.getFont().deriveFont(Font.PLAIN));
            btn.setMargin(new Insets(2, 10, 2, 10));
            btn.addActionListener(e -> updateFilter());
            typeFilterPanel.add(btn);
            filterButtons.put(type, btn);
        }

        filterBar.add(typeFilterPanel, BorderLayout.WEST);

        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        JLabel searchLabel = new JLabel("Search:");
        searchLabel.setFont(searchLabel.getFont().deriveFont(Font.BOLD));
        searchPanel.add(searchLabel);
        searchField = new JTextField(22);
        searchField.putClientProperty("JTextField.placeholderText", "Search all columns...");
        searchPanel.add(searchField);

        searchTimer = new javax.swing.Timer(300, e -> updateFilter());
        searchTimer.setRepeats(false);
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { searchTimer.restart(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { searchTimer.restart(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { searchTimer.restart(); }
        });

        filterBar.add(searchPanel, BorderLayout.EAST);
        headerPanel.add(filterBar);

        add(headerPanel, BorderLayout.NORTH);

        interactionTableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 5;
            }

            @Override
            public Class<?> getColumnClass(int column) {
                return column == 0 ? Integer.class : String.class;
            }
        };
        interactionTable = new JTable(interactionTableModel);
        interactionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        interactionTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showInteractionDetail();
            }
        });

        tableSorter = new TableRowSorter<>(interactionTableModel);
        tableSorter.setComparator(0, Comparator.naturalOrder());
        interactionTable.setRowSorter(tableSorter);

        interactionTable.getColumnModel().getColumn(0).setMaxWidth(50);
        interactionTable.getColumnModel().getColumn(0).setMinWidth(50);
        interactionTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        interactionTable.getColumnModel().getColumn(2).setMaxWidth(75);
        interactionTable.getColumnModel().getColumn(2).setMinWidth(75);
        interactionTable.getColumnModel().getColumn(2).setPreferredWidth(75);

        JPopupMenu tablePopup = new JPopupMenu();
        JMenuItem addCommentItem = new JMenuItem("Add comment");
        addCommentItem.addActionListener(e -> addComment());
        tablePopup.add(addCommentItem);
        JMenuItem clearItem = new JMenuItem("Clear interaction history");
        clearItem.addActionListener(e -> clearHistory());
        tablePopup.add(clearItem);
        JMenuItem exportItem = new JMenuItem("Export as CSV");
        exportItem.addActionListener(e -> exportCsv());
        tablePopup.add(exportItem);
        interactionTable.setComponentPopupMenu(tablePopup);

        JScrollPane tableScroll = new JScrollPane(interactionTable);

        detailTabs = new JTabbedPane();

        Font burpFont = UIManager.getFont("Label.font");
        if (burpFont == null) burpFont = new Font(Font.MONOSPACED, Font.PLAIN, 12);

        descArea = new JTextArea();
        descArea.setEditable(false);
        descArea.setFont(burpFont);
        descScroll = new JScrollPane(descArea);
        detailTabs.addTab("Description", descScroll);

        requestArea = new JTextArea();
        requestArea.setEditable(false);
        requestArea.setFont(burpFont);
        requestScroll = new JScrollPane(requestArea);

        httpReqEditor = api.userInterface().createHttpRequestEditor();
        requestPanel = new JPanel(new BorderLayout());
        requestPanel.add(requestScroll);
        detailTabs.addTab("Request", requestPanel);

        responseArea = new JTextArea();
        responseArea.setEditable(false);
        responseArea.setFont(burpFont);
        responseScroll = new JScrollPane(responseArea);

        httpRespEditor = api.userInterface().createHttpResponseEditor();
        responsePanel = new JPanel(new BorderLayout());
        responsePanel.add(responseScroll);
        detailTabs.addTab("Response", responsePanel);

        JSplitPane tableSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailTabs);
        tableSplit.setResizeWeight(0.7);
        tableSplit.setBorder(null);
        add(tableSplit, BorderLayout.CENTER);

        statusLabel = new JLabel(" ");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        statusLabel.setBorder(new EmptyBorder(6, 6, 6, 6));
        add(statusLabel, BorderLayout.SOUTH);
    }

    private void generateAndCopy() {
        if (isGenerating) return;
        isGenerating = true;
        statusLabel.setText("Generating payloads...");

        int count = (Integer) countSpinner.getValue();
        boolean includeServer = includeServerCb.isSelected();

        SwingWorker<String, Void> worker = new SwingWorker<>() {
            @Override
            protected String doInBackground() throws Exception {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < count; i++) {
                    String url = clientWrapper.generatePayload();
                    if (url == null || url.isEmpty()) continue;
                    if (includeServer) {
                        sb.append(url);
                    } else {
                        int lastDot = url.lastIndexOf('.');
                        int secondLastDot = url.lastIndexOf('.', lastDot - 1);
                        sb.append(url.substring(0, secondLastDot));
                    }
                    if (i < count - 1) sb.append("\n");
                }
                return sb.toString();
            }

            @Override
            protected void done() {
                try {
                    String result = get();
                    if (result.isEmpty()) {
                        statusLabel.setText("Error: empty payload");
                        return;
                    }
                    Toolkit.getDefaultToolkit().getSystemClipboard()
                            .setContents(new StringSelection(result), null);

                    String lines = result.split("\n").length > 1
                            ? result.split("\n").length + " payloads"
                            : "1 payload";
                    statusLabel.setText("Copied " + lines);
                } catch (Exception e) {
                    String msg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                    if (msg == null) msg = "Unknown error";
                    logger.error("Failed: " + msg);
                    statusLabel.setText("Error: " + msg);
                } finally {
                    isGenerating = false;
                }
            }
        };
        worker.execute();
    }

    private void pollInteractions() {
        if (clientWrapper.getPayloadCount() == 0) return;
        if (isPolling) return;

        isPolling = true;
        statusLabel.setText("Polling...");

        SwingWorker<List<InteractionData>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<InteractionData> doInBackground() throws Exception {
                return clientWrapper.pollInteractions();
            }

            @Override
            protected void done() {
                try {
                    List<InteractionData> interactions = get();
                    if (!interactions.isEmpty()) {
                        interactionList.addAll(interactions);
                        interactionCount += interactions.size();
                        appendToTable(interactions);
                    }
                    statusLabel.setText(interactionCount + " total interaction(s)");
                } catch (Exception e) {
                    String msg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                    if (msg == null) msg = "Unknown error";
                    logger.error("Poll failed: " + msg);
                    statusLabel.setText("Poll error: " + msg);
                } finally {
                    isPolling = false;
                }
            }
        };
        worker.execute();
    }

    private void updateFilter() {
        String searchText = searchField.getText().toLowerCase().trim();
        List<RowFilter<DefaultTableModel, Integer>> filters = new ArrayList<>();

        boolean anySelected = filterButtons.values().stream().anyMatch(AbstractButton::isSelected);
        if (anySelected) {
            RowFilter<DefaultTableModel, Integer> typeFilter = new RowFilter<>() {
                @Override
                public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                    String type = entry.getStringValue(2);
                    if (type == null) return false;
                    JToggleButton btn = filterButtons.get(type);
                    return btn != null && btn.isSelected();
                }
            };
            filters.add(typeFilter);
        }

        if (!searchText.isEmpty()) {
            RowFilter<DefaultTableModel, Integer> searchFilter = new RowFilter<>() {
                @Override
                public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                    for (int i = 0; i < entry.getValueCount(); i++) {
                        String val = entry.getStringValue(i);
                        if (val != null && val.toLowerCase().contains(searchText)) return true;
                    }
                    return false;
                }
            };
            filters.add(searchFilter);
        }

        tableSorter.setRowFilter(filters.isEmpty() ? null : RowFilter.andFilter(filters));
    }

    private void addComment() {
        int viewRow = interactionTable.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = interactionTable.convertRowIndexToModel(viewRow);

        String current = (String) interactionTableModel.getValueAt(modelRow, 5);
        String comment = JOptionPane.showInputDialog(this, "Enter comment:", current != null && !current.isEmpty() ? current : "");
        if (comment != null) {
            interactionTableModel.setValueAt(comment, modelRow, 5);
        }
    }

    private void clearHistory() {
        int ret = JOptionPane.showConfirmDialog(this, "Clear all interactions?", "Confirm",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ret != JOptionPane.YES_OPTION) return;
        interactionTableModel.setRowCount(0);
        interactionList.clear();
        interactionCount = 0;
        descArea.setText("");
        requestArea.setText("");
        responseArea.setText("");
        try {
            httpReqEditor.setRequest(HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: \r\n\r\n"));
            httpRespEditor.setResponse(
                    burp.api.montoya.http.message.responses.HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n"));
        } catch (Exception ignored) {}
        statusLabel.setText("");
    }

    private void exportCsv() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("interactions.csv"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        java.io.File file = fc.getSelectedFile();
        try (java.io.PrintWriter pw = new java.io.PrintWriter(file, "UTF-8")) {
            for (int c = 0; c < interactionTableModel.getColumnCount(); c++) {
                if (c > 0) pw.print(',');
                pw.print(escapeCsv(interactionTableModel.getColumnName(c)));
            }
            pw.println();
            for (int r = 0; r < interactionTableModel.getRowCount(); r++) {
                for (int c = 0; c < interactionTableModel.getColumnCount(); c++) {
                    if (c > 0) pw.print(',');
                    Object val = interactionTableModel.getValueAt(r, c);
                    pw.print(escapeCsv(val != null ? val.toString() : ""));
                }
                pw.println();
            }
            statusLabel.setText("Exported " + interactionTableModel.getRowCount() + " rows to " + file.getName());
        } catch (Exception e) {
            logger.error("CSV export failed: " + e.getMessage());
            statusLabel.setText("Export failed: " + e.getMessage());
        }
    }

    private static String escapeCsv(String s) {
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    private void appendToTable(List<InteractionData> interactions) {
        for (InteractionData interaction : interactions) {
            String time;
            try {
                time = ZonedDateTime.parse(interaction.getTimestamp()).format(TIME_FORMATTER);
            } catch (Exception e) {
                time = interaction.getTimestamp();
            }
            interactionTableModel.addRow(new Object[]{
                    interactionTableModel.getRowCount() + 1,
                    time,
                    interaction.getType(),
                    interaction.getPayload() != null ? interaction.getPayload() : interaction.getId(),
                    interaction.getClientIp(),
                    ""
            });
        }
    }

    private void showInteractionDetail() {
        int viewRow = interactionTable.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = interactionTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= interactionList.size()) return;

        InteractionData interaction = interactionList.get(modelRow);

        StringBuilder desc = new StringBuilder();
        desc.append("Type: ").append(interaction.getType()).append("\n");
        desc.append("Timestamp: ").append(interaction.getTimestamp()).append("\n");
        desc.append("Client IP: ").append(interaction.getClientIp()).append("\n");
        desc.append("ID: ").append(interaction.getId()).append("\n");
        if (interaction.getFullId() != null && !interaction.getFullId().isEmpty()) {
            desc.append("Full ID: ").append(interaction.getFullId()).append("\n");
        }
        if (interaction.getPayload() != null) {
            desc.append("Payload: ").append(interaction.getPayload()).append("\n");
        }
        descArea.setText(desc.toString());
        descArea.setCaretPosition(0);

        String type = interaction.getType();
        boolean hasReq = interaction.getRawRequest() != null && !interaction.getRawRequest().isEmpty();
        boolean hasResp = interaction.getRawResponse() != null && !interaction.getRawResponse().isEmpty();

        requestPanel.removeAll();
        responsePanel.removeAll();

        if ("HTTP".equals(type)) {
            detailTabs.setTitleAt(1, "Request to Collab");
            detailTabs.setTitleAt(2, "Response from Collab");
            if (hasReq) {
                try {
                    HttpRequest req = HttpRequest.httpRequest(interaction.getRawRequest());
                    httpReqEditor.setRequest(req);
                    requestPanel.add(httpReqEditor.uiComponent());
                } catch (Exception e) {
                    requestArea.setText(interaction.getRawRequest());
                    requestPanel.add(requestScroll);
                }
            } else {
                requestArea.setText("");
                requestPanel.add(requestScroll);
            }
            if (hasResp) {
                try {
                    burp.api.montoya.http.message.responses.HttpResponse resp =
                            burp.api.montoya.http.message.responses.HttpResponse.httpResponse(interaction.getRawResponse());
                    httpRespEditor.setResponse(resp);
                    responsePanel.add(httpRespEditor.uiComponent());
                } catch (Exception e) {
                    responseArea.setText(interaction.getRawResponse());
                    responsePanel.add(responseScroll);
                }
            } else {
                responseArea.setText("");
                responsePanel.add(responseScroll);
            }
            detailTabs.setEnabledAt(1, true);
            detailTabs.setEnabledAt(2, hasResp);
        } else if ("DNS".equals(type)) {
            requestArea.setText(hasReq ? interaction.getRawRequest() : "");
            requestArea.setCaretPosition(0);
            requestPanel.add(requestScroll);
            responseArea.setText("");
            responsePanel.add(responseScroll);
            detailTabs.setTitleAt(1, "DNS Query");
            detailTabs.setTitleAt(2, "Response from Collab");
            detailTabs.setEnabledAt(1, hasReq);
            detailTabs.setEnabledAt(2, false);
        } else if ("SMTP".equals(type)) {
            requestArea.setText(hasReq ? interaction.getRawRequest() : "");
            requestArea.setCaretPosition(0);
            requestPanel.add(requestScroll);
            responseArea.setText("");
            responsePanel.add(responseScroll);
            detailTabs.setTitleAt(1, "Conversation");
            detailTabs.setTitleAt(2, "Response from Collab");
            detailTabs.setEnabledAt(1, hasReq);
            detailTabs.setEnabledAt(2, false);
        } else {
            requestArea.setText("");
            requestPanel.add(requestScroll);
            responseArea.setText("");
            responsePanel.add(responseScroll);
            detailTabs.setTitleAt(1, "Request");
            detailTabs.setTitleAt(2, "Response");
            detailTabs.setEnabledAt(1, false);
            detailTabs.setEnabledAt(2, false);
        }

        detailTabs.setSelectedIndex(0);
        descArea.setCaretPosition(0);

        requestPanel.revalidate();
        requestPanel.repaint();
        responsePanel.revalidate();
        responsePanel.repaint();
    }
}
