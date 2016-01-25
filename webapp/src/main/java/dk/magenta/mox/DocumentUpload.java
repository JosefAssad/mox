package dk.magenta.mox;

import dk.magenta.mox.agent.*;
import dk.magenta.mox.json.JSONObject;
import dk.magenta.mox.spreadsheet.ConvertedObject;
import dk.magenta.mox.spreadsheet.SpreadsheetConverter;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

import javax.naming.OperationNotSupportedException;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Created by lars on 26-11-15.
 */
@WebServlet(name = "DocumentUpload")
@MultipartConfig
public class DocumentUpload extends UploadServlet {

    private MessageSender moxSender;
    private Properties agentProperties;
    private File cacheFolder;

    public void init() throws ServletException {

        File servletFilesystemBasePath = new File(this.getServletContext().getRealPath("/"));
        String servletWebBasePath = this.getServletContext().getContextPath();

        this.agentProperties = new Properties();
        try {
            this.agentProperties.load(this.getServletContext().getResourceAsStream("/WEB-INF/agent.properties"));
        } catch (IOException e) {
            throw new ServletException("Failed to load /WEB-INF/agent.properties",e);
        }
        String queueInterface = this.getPropertyOrThrow(this.agentProperties, "amqp.interface");
        String queueName = this.getPropertyOrThrow(this.agentProperties, "amqp.queue");
        String queueUsername = this.getPropertyOrThrow(this.agentProperties, "amqp.username");
        String queuePassword = this.getPropertyOrThrow(this.agentProperties, "amqp.password");

        this.cacheFolder = new File(servletFilesystemBasePath, this.getPropertyOrThrow(this.agentProperties, "file.cache"));

        if (!this.cacheFolder.exists()) {
            if (!this.cacheFolder.mkdirs()) {
                throw new ServletException("Misconfiguration: file.cache property points to a nonexistent directory '"+this.cacheFolder+"' => '"+this.cacheFolder.getAbsolutePath()+"' that could not be created");
            }
        } else if (!cacheFolder.isDirectory()) {
            throw new ServletException("Misconfiguration: file.cache property does not point to a directory");
        }

        try {
            this.moxSender = new MessageSender(queueUsername, queuePassword, queueInterface, null, queueName);
        } catch (IOException e) {
            throw new ServletException("Unable to connect to amqp queue '"+queueInterface+"/"+queueName+"'. Documents were not dispatched.", e);
        } catch (TimeoutException e) {
            throw new ServletException("Timeout when connecting to amqp queue '"+queueInterface+"/"+queueName+"'. Documents were not dispatched.", e);
        }
    }

    private String getPropertyOrThrow(Properties properties, String key) throws ServletException {
        String value = properties.getProperty(key);
        if (value == null) {
            throw new ServletException("Failed to get property '"+key+"' from configuration file");
        }
        return value;
    }


    Logger log = Logger.getLogger(DocumentUpload.class);

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        try {
            Writer output = response.getWriter();

            String authorization = request.getHeader("authorization");
            if (authorization == null) {
                authorization = request.getParameter("authtoken");
            }

            List<UploadedFile> files = this.getUploadFiles(request);

            HashMap<String, Future<String>> moxResponses = new HashMap<String, Future<String>>();
            for (UploadedFile file : files) {
                File cachedFile = new File(this.cacheFolder, file.getFilename());
                for (int i = 0; cachedFile.exists() && i<100000; i++) {
                    cachedFile = new File(this.cacheFolder, file.getFilename() + ".cache" + i);
                }
                boolean created = cachedFile.createNewFile();
                if (!created) {
                    throw new ServletException("Unable to create cache file "+cachedFile.getAbsolutePath());
                }
                if (!cachedFile.canWrite()) {
                    throw new ServletException("Cannot write to cache file "+ cachedFile.getAbsolutePath());
                }
                InputStream fileInput = file.getInputStream();
                FileOutputStream cacheOutput = new FileOutputStream(cachedFile);
                IOUtils.copy(fileInput, cacheOutput);
                fileInput.close();
                cacheOutput.close();

                JSONObject message = new JSONObject();
                message.put("url", this.getServletContext().getContextPath() + "/" + this.cacheFolder.getPath() + "/" + cachedFile.getPath());

                output.append(message.toString());
            }
/*
            for (String key : moxResponses.keySet()) {
                Future<String> moxResponse = moxResponses.get(key);
                String responseString;
                try {
                    responseString = moxResponse.get(30, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    throw new ServletException("Interruption error when interfacing with rest interface through message queue.\nWhen uploading " + key, e);
                } catch (ExecutionException e) {
                    throw new ServletException("Execution error when interfacing with rest interface through message queue.\nWhen uploading " + key, e);
                } catch (TimeoutException e) {
                    throw new ServletException("Timeout (30 seconds) when interfacing with rest interface through message queue.\nWhen uploading " + key, e);
                }
                if (responseString != null) {
                    JSONObject responseObject = new JSONObject(responseString);
                    if (responseObject != null) {
                        String errorType = responseObject.optString("type");
                        if (errorType != null && errorType.equalsIgnoreCase("ExecutionException")) {
                            throw new ServletException("Error from REST interface: " + responseObject.optString("message", responseString) + "\nWhen uploading " + key);
                        }
                    }

                    output.append(key + " => " + responseString);

                } else {
                    throw new ServletException("No response from REST interface\nWhen uploading " + key);
                }
            }*/
        } catch (ServletException e) {
            log.error("Error when receiving or parsing upload", e);
            throw e;
        }

    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Writer output = response.getWriter();
        output.append("<html>\n");
        output.append("<head>\n");
        output.append("<title>Mox document uploader</title>\n");
        output.append("</head>\n");
        output.append("<body>\n");
        output.append("<form action=\"DocumentUpload\" method=\"POST\" enctype=\"multipart/form-data\">\n");
        output.append("<label for=\"file\">Spreadsheet file:</label><br/>");
        output.append("<input type=\"file\" id=\"file\" name=\"file\"/><br/>\n");
        output.append("<label for=\"authtoken\">Authtoken:</label><br/>");
        output.append("<textarea name=\"authtoken\" id=\"authtoken\"></textarea><br/>\n");
        output.append("<input type=\"submit\" value=\"Upload\"/>\n");
        output.append("</form>\n");
        output.append("</body>\n");
        output.append("</html>\n");
    }

}
