package org.joget.marketplace;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.joget.apps.app.dao.FormDefinitionDao;
import org.joget.apps.app.model.FormDefinition;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppService;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.lib.FileUpload;
import org.joget.apps.form.model.Element;
import org.joget.apps.form.model.FileDownloadSecurity;
import org.joget.apps.form.model.Form;
import org.joget.apps.form.model.FormBuilderPalette;
import org.joget.apps.form.model.FormData;
import org.joget.apps.form.model.FormRow;
import org.joget.apps.form.model.FormRowSet;
import org.joget.apps.form.service.FileUtil;
import org.joget.apps.form.service.FormService;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.FileManager;
import org.joget.commons.util.FileStore;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.commons.util.StringUtil;
import org.joget.workflow.util.WorkflowUtil;
import org.json.JSONObject;
import org.springframework.web.multipart.MultipartFile;

public class EncryptedFileUpload extends FileUpload {

    private static final String MESSAGE_PATH = "messages/EncryptedFileUpload";
    private static final String DEFAULT_KEY_REFERENCE = "";
    private static final byte[] MAGIC = new byte[]{'J', 'E', 'F', 'U', '1'};
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_LENGTH = 12;
    private static final int BUFFER_SIZE = 65536;

    @Override
    public String getName() {
        return "Encrypted File Upload";
    }

    @Override
    public String getVersion() {
        return "9.0.0";
    }

    @Override
    public String getDescription() {
        return "Encrypted File Upload Element";
    }

    @Override
    public String getLabel() {
        return "Encrypted File Upload";
    }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClassName(), "/properties/encryptedFileUpload.json", null, true, MESSAGE_PATH);
    }

    @Override
    public String getFormBuilderCategory() {
        return "Marketplace";
    }

    @Override
    public String getFormBuilderTemplate() {
        return "<label class='label'>" + ResourceBundleUtil.getMessage("org.joget.marketplace.encryptedfileupload.pluginLabel") + "</label><input type='file' />";
    }

    @Override
    public String renderTemplate(FormData formData, Map dataModel) {
        String template = "fileUpload.ftl";

        String[] values = getRenderValues(formData);
        Map<String, String> tempFilePaths = new LinkedHashMap<String, String>();
        Map<String, String> filePaths = new LinkedHashMap<String, String>();

        String primaryKeyValue = getPrimaryKeyValue(formData);
        String filePathPostfix = "_path";
        String id = FormUtil.getElementParameterName(this);

        String[] tempExisting = formData.getRequestParameterValues(id + filePathPostfix);
        if (hasValue(tempExisting)) {
            values = tempExisting;
        }

        String appId = "";
        String appVersion = "";
        AppDefinition appDef = AppUtil.getCurrentAppDefinition();
        if (appDef != null) {
            appId = appDef.getId();
            appVersion = appDef.getVersion().toString();
        }

        String formDefId = "";
        String tableName = "";
        Form form = FormUtil.findRootForm(this);
        if (form != null) {
            formDefId = form.getPropertyString(FormUtil.PROPERTY_ID);
            tableName = form.getPropertyString(FormUtil.PROPERTY_TABLE_NAME);
        }

        if (!hasValue(values)) {
            values = loadValuesFromAppService(appId, appVersion, formDefId, primaryKeyValue);
        }

        for (String value : values) {
            File file = FileManager.getFileByPath(value);
            if (file != null) {
                tempFilePaths.put(value, file.getName());
            } else if (value != null && !value.isEmpty()) {
                filePaths.put(getEncryptedDownloadUrl(appId, appVersion, formDefId, tableName, primaryKeyValue, value), value);
            }
        }

        if (!tempFilePaths.isEmpty()) {
            dataModel.put("tempFilePaths", tempFilePaths);
        }
        if (!filePaths.isEmpty()) {
            dataModel.put("filePaths", filePaths);
        }

        return FormUtil.generateElementHtml(this, formData, template, dataModel);
    }

    protected String[] loadValuesFromAppService(String appId, String appVersion, String formDefId, String primaryKeyValue) {
        String id = getPropertyString(FormUtil.PROPERTY_ID);
        if (appId == null || appId.isEmpty() || appVersion == null || appVersion.isEmpty()
                || formDefId == null || formDefId.isEmpty() || primaryKeyValue == null || primaryKeyValue.isEmpty()
                || id == null || id.isEmpty()) {
            return new String[0];
        }

        try {
            AppService appService = (AppService) AppUtil.getApplicationContext().getBean("appService");
            FormRowSet rowSet = appService.loadFormData(appId, appVersion, formDefId, primaryKeyValue);
            if (rowSet != null && !rowSet.isEmpty()) {
                String value = rowSet.get(0).getProperty(id);
                if ((value == null || value.isEmpty()) && (Character.isDigit(id.charAt(0)) || javax.lang.model.SourceVersion.isKeyword(id))) {
                    value = rowSet.get(0).getProperty("t__" + id);
                }
                if (value != null && !value.trim().isEmpty()) {
                    return value.split(";");
                }
            }
        } catch (Exception ex) {
            LogUtil.error(getClassName(), ex, "Unable to load encrypted file upload value from app service.");
        }
        return new String[0];
    }

    protected String[] getRenderValues(FormData formData) {
        String id = getPropertyString(FormUtil.PROPERTY_ID);
        String[] values = FormUtil.getElementPropertyValues(this, formData);

        if (!hasValue(values) && formData != null && id != null) {
            String binderValue = formData.getLoadBinderDataProperty(this, id);
            if (binderValue != null && !binderValue.trim().isEmpty()) {
                values = binderValue.split(";");
            }
        }

        if (!hasValue(values) && formData != null && id != null) {
            Form form = FormUtil.findRootForm(this);
            if (form != null) {
                String binderValue = formData.getLoadBinderDataProperty(form, id);
                if (binderValue == null && (Character.isDigit(id.charAt(0)) || javax.lang.model.SourceVersion.isKeyword(id))) {
                    binderValue = formData.getLoadBinderDataProperty(form, "t__" + id);
                }
                if (binderValue != null && !binderValue.trim().isEmpty()) {
                    values = binderValue.split(";");
                }
            }
        }

        if (!hasValue(values) && formData != null) {
            String storedValue = formData.getStoreBinderDataProperty(this);
            if (storedValue != null && !storedValue.trim().isEmpty()) {
                values = storedValue.split(";");
            }
        }

        return values;
    }

    protected boolean hasValue(String[] values) {
        if (values == null || values.length == 0) {
            return false;
        }
        for (String value : values) {
            if (value != null && !value.trim().isEmpty()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public FormRowSet formatData(FormData formData) {
        FormRowSet rowSet = super.formatData(formData);
        if (rowSet == null) {
            return null;
        }

        String keyReference = getKeyReference();
        try {
            SecretKeySpec key = getSecretKey(keyReference, AppUtil.getCurrentAppDefinition());
            for (FormRow row : rowSet) {
                Map<String, String[]> tempFilePathMap = row.getTempFilePathMap();
                if (tempFilePathMap == null || tempFilePathMap.isEmpty()) {
                    continue;
                }
                for (String fieldId : tempFilePathMap.keySet()) {
                    String[] paths = tempFilePathMap.get(fieldId);
                    if (paths == null) {
                        continue;
                    }
                    for (String path : paths) {
                        File file = FileManager.getFileByPath(path);
                        if (file != null && file.exists() && !isEncrypted(file)) {
                            encryptFileInPlace(file, key);
                        }
                    }
                }
            }
        } catch (Exception ex) {
            String id = FormUtil.getElementParameterName(this);
            formData.addFormError(id, ResourceBundleUtil.getMessage("org.joget.marketplace.encryptedfileupload.encryptionError"));
            LogUtil.error(getClassName(), ex, "Unable to encrypt uploaded file. Check configured encryption key.");
            return null;
        }

        return rowSet;
    }

    @Override
    public String getServiceUrl() {
        String url = WorkflowUtil.getHttpServletRequest().getContextPath() + "/web/json/plugin/" + getClassName() + "/service";
        AppDefinition appDef = AppUtil.getCurrentAppDefinition();

        String appId = appDef != null ? appDef.getAppId() : "";
        String appVersion = appDef != null ? appDef.getVersion().toString() : "";
        String paramName = FormUtil.getElementParameterName(this);
        String fileType = getPropertyString("fileType");
        String nonce = SecurityUtil.generateNonce(new String[]{"EncryptedFileUpload", appId, appVersion, paramName, fileType}, 1);

        try {
            url = url + "?_nonce=" + URLEncoder.encode(nonce, "UTF-8")
                    + "&_paramName=" + URLEncoder.encode(paramName, "UTF-8")
                    + "&_appId=" + URLEncoder.encode(appId, "UTF-8")
                    + "&_appVersion=" + URLEncoder.encode(appVersion, "UTF-8")
                    + "&_ft=" + URLEncoder.encode(fileType, "UTF-8");
        } catch (Exception ex) {
            LogUtil.error(getClassName(), ex, ex.getMessage());
        }
        return url;
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String action = request.getParameter("action");
        if ("download".equals(action)) {
            handleEncryptedDownload(request, response);
            return;
        }

        handleUploadService(request, response);
    }

    protected void handleUploadService(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String nonce = request.getParameter("_nonce");
        String paramName = request.getParameter("_paramName");
        String appId = request.getParameter("_appId");
        String appVersion = request.getParameter("_appVersion");
        String filePath = request.getParameter("_path");
        String fileType = request.getParameter("_ft");

        if (!SecurityUtil.verifyNonce(nonce, new String[]{"EncryptedFileUpload", appId, appVersion, paramName, fileType})) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, ResourceBundleUtil.getMessage("general.error.error403"));
            return;
        }

        if ("POST".equalsIgnoreCase(request.getMethod())) {
            try {
                JSONObject obj = new JSONObject();
                try {
                    String validatedParamName = SecurityUtil.validateStringInput(paramName);
                    MultipartFile file = FileStore.getFile(validatedParamName);
                    if (file != null && file.getOriginalFilename() != null && !file.getOriginalFilename().isEmpty()) {
                        String originalFilename = file.getOriginalFilename();
                        String ext = "";
                        int dot = originalFilename.lastIndexOf(".");
                        if (dot >= 0) {
                            ext = originalFilename.substring(dot).toLowerCase();
                        }
                        if (fileType != null && (fileType.isEmpty() || fileType.contains(ext + ";") || fileType.endsWith(ext))) {
                            String path = FileManager.storeFile(file);
                            obj.put("path", path);
                            obj.put("filename", originalFilename);
                            obj.put("newFilename", path.substring(path.lastIndexOf(File.separator) + 1));
                        } else {
                            obj.put("error", ResourceBundleUtil.getMessage("form.fileupload.fileType.msg.invalidFileType"));
                        }
                    }

                    if (FileStore.getFileErrorList() != null && FileStore.getFileErrorList().contains(paramName)) {
                        obj.put("error", ResourceBundleUtil.getMessage("general.error.fileSizeTooLarge", new Object[]{FileStore.getFileSizeLimit()}));
                    }
                } catch (Exception ex) {
                    obj.put("error", ex.getLocalizedMessage());
                } finally {
                    FileStore.clear();
                }
                obj.write(response.getWriter());
            } catch (Exception ex) {
                LogUtil.error(getClassName(), ex, ex.getMessage());
            }
        } else if (filePath != null && !filePath.isEmpty()) {
            streamPlainTempFile(request, response, filePath);
        }
    }

    protected void handleEncryptedDownload(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String encryptedParams = request.getParameter("params");
            String params = SecurityUtil.decrypt(encryptedParams);
            JSONObject json = new JSONObject(params);

            String nonce = json.optString("nonce");
            String appId = json.optString("appId");
            String appVersion = json.optString("appVersion");
            String formDefId = json.optString("formDefId");
            String primaryKeyValue = json.optString("primaryKeyValue");
            String fileName = json.optString("fileName");
            String fieldId = json.optString("fieldId");

            if (!SecurityUtil.verifyNonce(nonce, new String[]{"EncryptedFileUploadDownload", appId, appVersion, formDefId, primaryKeyValue, fileName, fieldId})) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, ResourceBundleUtil.getMessage("general.error.error403"));
                return;
            }

            DownloadContext download = getDownloadContext(request, appId, appVersion, formDefId, primaryKeyValue, fileName, fieldId);
            if (download == null || download.field == null || download.tableName == null) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }
            if (!download.authorized) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, ResourceBundleUtil.getMessage("general.error.error403"));
                return;
            }

            File file = FileUtil.getFile(download.decodedFileName, download.tableName, primaryKeyValue);
            if (file == null || !file.exists()) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }

            SecretKeySpec key = download.field.getSecretKey(download.field.getKeyReference(), download.appDef);
            streamDecryptedFile(request, response, file, download.decodedFileName, key, Boolean.valueOf(download.field.getPropertyString("attachment")));
        } catch (Exception ex) {
            LogUtil.error(getClassName(), ex, "Unable to decrypt uploaded file");
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ResourceBundleUtil.getMessage("org.joget.marketplace.encryptedfileupload.decryptionError"));
        }
    }

    protected String getEncryptedDownloadUrl(String appId, String appVersion, String formDefId, String tableName, String primaryKeyValue, String fileName) {
        JSONObject json = new JSONObject();
        json.put("appId", appId);
        json.put("appVersion", appVersion);
        json.put("formDefId", formDefId);
        json.put("primaryKeyValue", primaryKeyValue);
        json.put("fileName", fileName);
        json.put("fieldId", getPropertyString(FormUtil.PROPERTY_ID));

        String nonce = SecurityUtil.generateNonce(new String[]{"EncryptedFileUploadDownload", appId, appVersion, formDefId, primaryKeyValue, fileName, getPropertyString(FormUtil.PROPERTY_ID)}, 60);
        json.put("nonce", nonce);

        String params = StringUtil.escapeString(SecurityUtil.encrypt(json.toString()), StringUtil.TYPE_URL, null);
        return "/web/json/app/" + appId + "/" + appVersion + "/plugin/" + getClassName() + "/service?action=download&params=" + params;
    }

    protected DownloadContext getDownloadContext(HttpServletRequest request, String appId, String appVersion, String formDefId, String primaryKeyValue, String fileName, String fieldId) throws Exception {
        DownloadContext download = new DownloadContext();
        download.decodedFileName = fileName;
        try {
            download.decodedFileName = URLDecoder.decode(fileName, "UTF8");
        } catch (Exception ex) {
            // ignore
        }
        if (download.decodedFileName.endsWith(".")) {
            download.decodedFileName = download.decodedFileName.substring(0, download.decodedFileName.length() - 1);
        }

        AppService appService = (AppService) AppUtil.getApplicationContext().getBean("appService");
        FormDefinitionDao formDefinitionDao = (FormDefinitionDao) AppUtil.getApplicationContext().getBean("formDefinitionDao");
        FormService formService = (FormService) AppUtil.getApplicationContext().getBean("formService");

        if (appVersion == null || appVersion.isEmpty()) {
            Long publishedVersion = appService.getPublishedVersion(appId);
            if (publishedVersion != null) {
                appVersion = publishedVersion.toString();
            }
        }

        download.appDef = appService.getAppDefinition(appId, appVersion);
        FormDefinition formDef = formDefinitionDao.loadById(formDefId, download.appDef);
        if (formDef == null) {
            return null;
        }

        Form form = (Form) formService.createElementFromJson(formDef.getJson());
        if (form == null || form.getLoadBinder() == null) {
            return null;
        }

        download.tableName = form.getPropertyString(FormUtil.PROPERTY_TABLE_NAME);
        FormData formData = new FormData();
        FormRowSet rows = form.getLoadBinder().load(form, primaryKeyValue, formData);
        if (rows == null || rows.isEmpty()) {
            return null;
        }

        FormRow row = rows.get(0);
        String matchedFieldId = null;
        for (Object key : row.keySet()) {
            String rowFieldId = key.toString();
            String value = row.getProperty(rowFieldId);
            if (isFileValueMatch(value, formDefId, primaryKeyValue, download.decodedFileName)) {
                if (rowFieldId.startsWith("t__")) {
                    rowFieldId = rowFieldId.substring(3);
                }
                if (fieldId == null || fieldId.isEmpty() || fieldId.equals(rowFieldId)) {
                    matchedFieldId = rowFieldId;
                    break;
                }
            }
        }
        if (matchedFieldId == null) {
            return null;
        }

        FormData securityFormData = new FormData();
        Element element = FormUtil.findElement(matchedFieldId, form, securityFormData);
        if (!(element instanceof EncryptedFileUpload)) {
            return null;
        }

        download.field = (EncryptedFileUpload) element;
        if (element instanceof FileDownloadSecurity) {
            download.authorized = ((FileDownloadSecurity) element).isDownloadAllowed(request.getParameterMap());
        } else {
            download.authorized = !WorkflowUtil.isCurrentUserAnonymous();
        }
        return download;
    }

    protected boolean isFileValueMatch(String value, String formDefId, String primaryKeyValue, String fileName) {
        if (value == null || fileName == null) {
            return false;
        }

        String compareValue = fileName;
        if (compareValue.endsWith(FileManager.THUMBNAIL_EXT)) {
            compareValue = compareValue.replace(FileManager.THUMBNAIL_EXT, "");
        }

        return value.equals(compareValue)
                || (value.contains(";")
                    && (value.startsWith(compareValue + ";")
                        || value.contains(";" + compareValue + ";")
                        || value.endsWith(";" + compareValue)))
                || value.contains(formDefId + "/" + primaryKeyValue + "/" + compareValue)
                || value.contains(FileUtil.PATH_VARIABLE + compareValue);
    }

    protected String getKeyReference() {
        String keyReference = getPropertyString("encryptionKey");
        if (keyReference == null || keyReference.trim().isEmpty()) {
            return DEFAULT_KEY_REFERENCE;
        }
        return keyReference.trim();
    }

    protected SecretKeySpec getSecretKey(String keyReference, AppDefinition appDef) {
        String value = AppUtil.processHashVariable(keyReference, null, null, null, appDef);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalStateException("Missing encryption key.");
        }

        value = value.trim();
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(value);
            if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
                keyBytes = value.getBytes(StandardCharsets.UTF_8);
            }
        } catch (IllegalArgumentException ex) {
            keyBytes = value.getBytes(StandardCharsets.UTF_8);
        }

        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
            try {
                keyBytes = MessageDigest.getInstance("SHA-256").digest(keyBytes);
            } catch (GeneralSecurityException ex) {
                throw new IllegalStateException("Unable to derive AES key.", ex);
            }
        }
        return new SecretKeySpec(keyBytes, "AES");
    }

    protected void encryptFileInPlace(File file, SecretKeySpec key) throws IOException, GeneralSecurityException {
        File encrypted = new File(file.getParentFile(), file.getName() + ".encrypted.tmp");
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

        try (InputStream in = new BufferedInputStream(new FileInputStream(file));
                OutputStream fileOut = new BufferedOutputStream(new FileOutputStream(encrypted));
                CipherOutputStream cipherOut = new CipherOutputStream(fileOut, cipher)) {
            fileOut.write(MAGIC);
            fileOut.write(iv.length);
            fileOut.write(iv);
            copy(in, cipherOut);
        }

        if (!file.delete() || !encrypted.renameTo(file)) {
            throw new IOException("Unable to replace uploaded file with encrypted content: " + file.getAbsolutePath());
        }
    }

    protected void streamDecryptedFile(HttpServletRequest request, HttpServletResponse response, File file, String fileName, SecretKeySpec key, boolean attachment) throws IOException, GeneralSecurityException {
        String contentType = request.getSession().getServletContext().getMimeType(fileName);
        if (contentType != null) {
            response.setContentType(contentType);
        }
        if (attachment) {
            response.setHeader("Content-Disposition", "attachment; filename=\"" + fileName.replace("\"", "\\\"") + "\"");
        }

        try (InputStream in = new BufferedInputStream(new FileInputStream(file));
                ServletOutputStream out = response.getOutputStream()) {
            InputStream payload = getPayloadInputStream(in, key);
            copy(payload, out);
            out.flush();
        }
    }

    protected InputStream getPayloadInputStream(InputStream in, SecretKeySpec key) throws IOException, GeneralSecurityException {
        byte[] magic = readBytes(in, MAGIC.length);
        if (!matchesMagic(magic)) {
            return new SequenceInputStream(magic, in);
        }

        int ivLength = in.read();
        if (ivLength <= 0) {
            throw new IOException("Invalid encrypted file header");
        }

        byte[] iv = readBytes(in, ivLength);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return new CipherInputStream(in, cipher);
    }

    protected boolean isEncrypted(File file) throws IOException {
        if (file.length() < MAGIC.length) {
            return false;
        }
        try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
            return matchesMagic(readBytes(in, MAGIC.length));
        }
    }

    protected void streamPlainTempFile(HttpServletRequest request, HttpServletResponse response, String filePath) throws IOException {
        String normalizedFilePath = SecurityUtil.normalizedFileName(filePath);
        File file = FileManager.getFileByPath(normalizedFilePath);
        if (file == null || !file.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        String contentType = request.getSession().getServletContext().getMimeType(file.getName());
        if (contentType != null) {
            response.setContentType(contentType);
        }

        try (InputStream in = new BufferedInputStream(new FileInputStream(file));
                ServletOutputStream out = response.getOutputStream()) {
            copy(in, out);
            out.flush();
        }
    }

    protected byte[] readBytes(InputStream in, int length) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(length);
        byte[] buffer = new byte[length];
        while (out.size() < length) {
            int read = in.read(buffer, 0, length - out.size());
            if (read == -1) {
                break;
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    protected boolean matchesMagic(byte[] bytes) {
        if (bytes == null || bytes.length != MAGIC.length) {
            return false;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (bytes[i] != MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    protected void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        int length;
        while ((length = in.read(buffer)) != -1) {
            out.write(buffer, 0, length);
        }
    }

    protected static class SequenceInputStream extends InputStream {

        private final byte[] prefix;
        private final InputStream delegate;
        private int index = 0;

        SequenceInputStream(byte[] prefix, InputStream delegate) {
            this.prefix = prefix != null ? prefix : new byte[0];
            this.delegate = delegate;
        }

        @Override
        public int read() throws IOException {
            if (index < prefix.length) {
                return prefix[index++] & 0xff;
            }
            return delegate.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (index < prefix.length) {
                int count = Math.min(len, prefix.length - index);
                System.arraycopy(prefix, index, b, off, count);
                index += count;
                return count;
            }
            return delegate.read(b, off, len);
        }
    }

    protected static class DownloadContext {

        AppDefinition appDef;
        EncryptedFileUpload field;
        String tableName;
        String decodedFileName;
        boolean authorized;
    }
}
