package org.joget.marketplace.form.encryptedfileupload;

import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppPluginUtil;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.datalist.model.DataList;
import org.joget.apps.datalist.model.DataListColumn;
import org.joget.apps.datalist.model.DataListColumnFormatDefault;
import org.joget.apps.datalist.service.DataListService;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.commons.util.StringUtil;
import org.json.JSONObject;

public class EncryptedFileDatalistFormatter extends DataListColumnFormatDefault {

    private static final String MESSAGE_PATH = "messages/EncryptedFileDatalistFormatter";

    @Override
    public String getName() {
        return AppPluginUtil.getMessage("org.joget.marketplace.encryptedfiledatalistformatter.pluginLabel", getClassName(), MESSAGE_PATH);
    }

    @Override
    public String getVersion() {
        return Activator.VERSION;
    }

    @Override
    public String getDescription() {
        return AppPluginUtil.getMessage("org.joget.marketplace.encryptedfiledatalistformatter.pluginDesc", getClassName(), MESSAGE_PATH);
    }

    @Override
    public String getLabel() {
        return AppPluginUtil.getMessage("org.joget.marketplace.encryptedfiledatalistformatter.pluginLabel", getClassName(), MESSAGE_PATH);
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClassName(), "/properties/encryptedFileDatalistFormatter.json", null, true, MESSAGE_PATH);
    }

    @Override
    public String format(DataList dataList, DataListColumn column, Object row, Object value) {
        String result = (value != null) ? value.toString() : "";
        if (result.isEmpty()) {
            return result;
        }

        try {
            AppDefinition appDef = AppUtil.getCurrentAppDefinition();
            if (appDef == null) {
                return result;
            }
            
            String appId = appDef.getId();
            String appVersion = appDef.getVersion().toString();
            
            // Get formDefId from properties or detect from binder
            String formDefId = getPropertyString("formDefId");
            if (formDefId == null || formDefId.isEmpty()) {
                if (dataList.getBinder() != null) {
                    formDefId = dataList.getBinder().getPropertyString("formId");
                }
            }
            
            if (formDefId == null || formDefId.isEmpty()) {
                return result; 
            }

            // Detect fieldId from column
            String fieldId = column.getName();
            if (fieldId != null && fieldId.startsWith("c_")) {
                fieldId = fieldId.substring(2);
            }
            
            String primaryKeyField = dataList.getBinder().getPrimaryKeyColumnName();
            String primaryKeyValue = "";
            
            Object pkv = DataListService.evaluateColumnValueFromRow(row, primaryKeyField);
            if (pkv != null) {
                primaryKeyValue = pkv.toString();
            }
            
            if (primaryKeyValue.isEmpty()) {
                pkv = DataListService.evaluateColumnValueFromRow(row, "id");
                if (pkv != null) {
                    primaryKeyValue = pkv.toString();
                }
            }

            if (primaryKeyValue.isEmpty()) {
                return result;
            }

            StringBuilder formattedValue = new StringBuilder();
            String[] filenames = result.split(";");
            boolean downloadAsAttachment = "true".equalsIgnoreCase(getPropertyString("downloadAsAttachment"));
            
            for (String filename : filenames) {
                if (filename.trim().isEmpty()) {
                    continue;
                }
                
                String url = getEncryptedDownloadUrl(appId, appVersion, formDefId, primaryKeyValue, filename.trim(), fieldId);
                if (formattedValue.length() > 0) {
                    formattedValue.append("<br/>");
                }
                
                String label = filename;
                if (label.contains("/")) {
                    label = label.substring(label.lastIndexOf("/") + 1);
                }
                
                formattedValue.append("<a href=\"").append(url).append("\"");
                if (!downloadAsAttachment) {
                    formattedValue.append(" target=\"_blank\"");
                }
                formattedValue.append(">").append(StringUtil.escapeString(label, StringUtil.TYPE_HTML, null)).append("</a>");
            }
            
            return formattedValue.toString();
        } catch (Exception e) {
            LogUtil.error(getClassName(), e, "Error formatting encrypted file upload column");
        }

        return result;
    }

    protected String getEncryptedDownloadUrl(String appId, String appVersion, String formDefId, String primaryKeyValue, String fileName, String fieldId) {
        JSONObject json = new JSONObject();
        json.put("appId", appId);
        json.put("appVersion", appVersion);
        json.put("formDefId", formDefId);
        json.put("primaryKeyValue", primaryKeyValue);
        json.put("fileName", fileName);
        json.put("fieldId", fieldId);
        
        // Explicitly set attachment value
        boolean downloadAsAttachment = "true".equalsIgnoreCase(getPropertyString("downloadAsAttachment"));
        json.put("attachment", downloadAsAttachment);

        String nonce = SecurityUtil.generateNonce(new String[]{"EncryptedFileUploadDownload", appId, appVersion, formDefId, primaryKeyValue, fileName, fieldId}, 60);
        json.put("nonce", nonce);

        // Process key only if provided
        String formatterKey = getPropertyString("encryptionKey");
        if (formatterKey != null && !formatterKey.isEmpty()) {
            json.put("encryptionKey", AppUtil.processHashVariable(formatterKey, null, null, null).trim());
        }

        String params = StringUtil.escapeString(SecurityUtil.encrypt(json.toString()), StringUtil.TYPE_URL, null);
        return AppUtil.getRequestContextPath() + "/web/json/app/" + appId + "/" + appVersion + "/plugin/org.joget.marketplace.form.encryptedfileupload.EncryptedFileUpload/service?action=download&params=" + params;
    }
}
