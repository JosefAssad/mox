package dk.magenta.mox.upload;

/**
 * Created by lars on 22-01-16.
 */
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.IOUtils;

@WebServlet("/UploadServlet")
public class UploadServlet extends HttpServlet {
    private ServletFileUpload uploader = null;

    public static final String UPLOAD_SERVLET_URL = "UploadServlet";
    public static final String cacheFolderNameConfigKey = "FILES_DIR";

    private InetAddress localAddress;
    private static Pattern hostnamePattern = Pattern.compile("[a-z]+://([a-z0-9\\-\\.]+)/.*", Pattern.CASE_INSENSITIVE);


    @Override
    public void init() throws ServletException {
        File cacheFolder = new File((String) getServletContext().getAttribute(cacheFolderNameConfigKey));

        if (!cacheFolder.isDirectory()) {
            throw new ServletException("Configured cacheFolder '"+cacheFolder.getAbsolutePath()+"' is not a directory");
        }
        if (!cacheFolder.canWrite()) {
            throw new ServletException("Configured cacheFolder '"+cacheFolder.getAbsolutePath()+"' is not writable");
        }

        DiskFileItemFactory fileFactory = new DiskFileItemFactory();
        fileFactory.setRepository(cacheFolder);

        this.uploader = new ServletFileUpload(fileFactory);

        try {
            this.localAddress = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }


    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String fileName = request.getParameter("fileName");
        if (fileName == null || fileName.equals("")){
            throw new ServletException("File Name can't be null or empty");
        }
        File file = new File(request.getServletContext().getAttribute(cacheFolderNameConfigKey) + File.separator + fileName);
        if (!file.exists()) {
            throw new ServletException("File doesn't exists on server.");
        }
        ServletContext ctx = getServletContext();
        InputStream fis = new FileInputStream(file);
        String mimeType = ctx.getMimeType(file.getAbsolutePath());
        response.setContentType(mimeType != null ? mimeType : "application/octet-stream");
        response.setContentLength((int) file.length());
        response.setHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");

        ServletOutputStream os = response.getOutputStream();
        IOUtils.copy(fis, os);

        os.flush();
        os.close();
        fis.close();
    }


    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if(!ServletFileUpload.isMultipartContent(request)){
            throw new ServletException("Content type is not multipart/form-data");
        }

        ArrayList<UploadedDocumentMessage> messages = new ArrayList<>();

        String protocol = request.getProtocol().replaceAll("/.*","");

        String hostname;
        Matcher m = hostnamePattern.matcher(request.getRequestURL().toString());
        if (m.find()) {
            hostname = m.group(1);
        } else {
            hostname = this.localAddress.getHostName();
        }

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.write("<html><head></head><body>");
        try {
            List<FileItem> fileItemsList = uploader.parseRequest(request);
            Iterator<FileItem> fileItemsIterator = fileItemsList.iterator();
            while (fileItemsIterator.hasNext()) {
                FileItem fileItem = fileItemsIterator.next();
                File file = new File(request.getServletContext().getAttribute(cacheFolderNameConfigKey) + File.separator + fileItem.getName());
                fileItem.write(file);

                String relativePath = UPLOAD_SERVLET_URL + "?fileName=" + fileItem.getName();

                out.write("File " + fileItem.getName() + " uploaded successfully.");
                out.write("<br/>");
                out.write("<a href=\"" + relativePath + "\">Download " + fileItem.getName() + "</a>");

                String path = this.getServletContext().getContextPath() + "/" + relativePath;
                UploadedDocumentMessage message = new UploadedDocumentMessage(fileItem.getName(), new URL(protocol, hostname, path));
                System.out.println(message.toJSON());
                messages.add(message);
            }
        } catch (FileUploadException e) {
            out.write("Exception in uploading file.");
            throw new ServletException(e);
        } catch (Exception e) {
            out.write("Exception in uploading file.");
            throw new ServletException(e);
        }
        out.write("</body></html>");
    }

}