import hudson.Extension
import hudson.model.Descriptor
import hudson.util.FormValidation
import jenkins.model.GlobalConfiguration
import org.kohsuke.stapler.DataBoundConstructor
import org.kohsuke.stapler.QueryParameter
import org.apache.commons.io.IOUtils
import javax.servlet.ServletException
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.SSLContext
import java.nio.file.Files
import java.nio.file.Paths
import org.kohsuke.stapler.StaplerRequest
import net.sf.json.JSONObject

@Extension
public class CertificateUploader extends GlobalConfiguration {

    private String uploadedCertificate;

    @DataBoundConstructor
    public CertificateUploader(String uploadedCertificate) {
        this.uploadedCertificate = uploadedCertificate;
        // Una vez cargado el certificado, lo agregamos al truststore
        if (uploadedCertificate != null && !uploadedCertificate.isEmpty()) {
            addCertificateToTrustStore(uploadedCertificate);
        }
    }

    public String getUploadedCertificate() {
        return uploadedCertificate;
    }

    public void setUploadedCertificate(String uploadedCertificate) {
        this.uploadedCertificate = uploadedCertificate;
    }

    // Método para agregar el certificado al truststore
    private void addCertificateToTrustStore(String certContent) {
        try {
            // Convertir el contenido del certificado en bytes
            byte[] certBytes = certContent.getBytes("UTF-8");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

            // Cargar el truststore actual
            String trustStorePath = System.getProperty("javax.net.ssl.trustStore", "${System.getProperty('java.home')}/lib/security/cacerts");
            String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword", "changeit");

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());

            // Insertar el certificado en el truststore
            String alias = "custom-cert-alias"; // Alias personalizado
            trustStore.setCertificateEntry(alias, cert);

            // Guardar el truststore modificado
            trustStore.store(new FileOutputStream(trustStorePath), trustStorePassword.toCharArray());

            // Configurar el contexto SSL de la JVM
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            // Aplicar el nuevo contexto SSL globalmente
            SSLContext.setDefault(sslContext);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Este método define la UI de configuración en el panel de administración de Jenkins
    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
        req.bindJSON(this, json);
        save();
        return true;
    }

    // Validación para asegurarse de que el certificado esté en un formato válido
    public FormValidation doCheckUploadedCertificate(@QueryParameter String value) throws IOException, ServletException {
        if (value == null || value.isEmpty()) {
            return FormValidation.error("Por favor, suba un certificado.");
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cf.generateCertificate(new ByteArrayInputStream(value.getBytes("UTF-8")));
            return FormValidation.ok();
        } catch (Exception e) {
            return FormValidation.error("Certificado no válido. Asegúrese de que sea un certificado X.509 válido.");
        }
    }
}
