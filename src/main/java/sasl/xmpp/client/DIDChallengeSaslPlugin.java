package sasl.xmpp.client;

import demo.sasl.client.SaslClientCallbackHandler;
import demo.sasl.client.integration.UserIntegrationWithDID;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jivesoftware.smack.ConnectionListener;
import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.sasl.SASLMechanism;
import org.jivesoftware.smack.sasl.javax.SASLJavaXMechanism;
import org.jivesoftware.smack.sasl.javax.SmackJavaxSaslException;
import org.jivesoftware.spark.SparkManager;
import org.jivesoftware.spark.plugin.Invokable;
import org.jivesoftware.spark.plugin.Plugin;
import org.jivesoftware.sparkimpl.settings.local.SettingsManager;
import sasl.mechanism.did.DIDChallengeSaslProvider;
import sasl.xmpp.client.debug.SaslClientDebug;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.swing.*;
import java.security.Security;
import java.util.Arrays;
import java.util.Map;

public class DIDChallengeSaslPlugin implements Plugin, Invokable, ConnectionListener {

    private static final Logger log = LogManager.getLogger(DIDChallengeSaslPlugin.class);

    static {
        Security.addProvider(new DIDChallengeSaslProvider());
    }

    static {
        SaslClientDebug.logSaslClientFactoriesAndMechanisms();
    }

    static {
        SASLAuthentication.registerSASLMechanism(new SASLDIDChallengeJavaXMechanism());
        log.debug("SASL mechanisms: " + SASLAuthentication.getRegisterdSASLMechanisms());
    }

    static {
        SparkManager.getConnection().addConnectionListener(new DIDChallengeSaslPlugin());
    }

    @Override
    public void initialize() {
        log.debug("initialize");
        JOptionPane.showMessageDialog(null, "DID-CHALLENGE SASL mechanism: initialize");
    }

    @Override
    public void shutdown() {
        log.debug("shutdown");
        JOptionPane.showMessageDialog(null, "DID-CHALLENGE SASL mechanism: shutdown");
    }

    @Override
    public boolean canShutDown() {
        log.debug("canShutDown");
        JOptionPane.showMessageDialog(null, "DID-CHALLENGE SASL mechanism: canShutDown");
        return true;
    }

    @Override
    public void uninstall() {
        log.debug("uninstall");
        JOptionPane.showMessageDialog(null, "DID-CHALLENGE SASL mechanism: uninstall");
    }

    @Override
    public void connecting(XMPPConnection connection) {
        log.debug("connecting: " + connection);
        JOptionPane.showMessageDialog(null, "DID-CHALLENGE SASL mechanism: connecting: " + connection);
        ConnectionListener.super.connecting(connection);
    }

    @Override
    public boolean invoke(Object... objects) {
        log.debug("invoke: " + Arrays.asList(objects));
        return false;
    }

    /*
     * Helper classes
     */

    private static class SASLDIDChallengeJavaXMechanism extends SASLJavaXMechanism {

        @Override
        public String getName() {
            return DIDChallengeSaslProvider.MECHANISM_NAME;
        }

        @Override
        public int getPriority() {
            return 0;
        }

        @Override
        protected SASLMechanism newInstance() {
            return new SASLDIDChallengeJavaXMechanism();
        }

        @Override
        public boolean requiresPassword() {
            return false;
        }

        @Override
        protected void authenticateInternal() throws SmackJavaxSaslException {
            String[] mechanisms = { getName() };
            Map<String, String> props = getSaslProps();
            String authzid = null;
            if (authorizationId != null) {
                authzid = authorizationId.toString();
            }
            try {
                sc = Sasl.createSaslClient(mechanisms, authzid, "xmpp", getServerName().toString(), props,
                        new SaslClientCallbackHandler(new UserIntegrationWithDID()));
            }
            catch (SaslException e) {
                throw new SmackJavaxSaslException(e);
            }
        }

        @Override
        protected void authenticateInternal(CallbackHandler cbh) throws SmackJavaxSaslException {
            super.authenticateInternal(cbh);
            log.info("authenticateInternal " + cbh + " -> " + this.sc);
        }

        @Override
        protected byte[] getAuthenticationText() throws SmackJavaxSaslException {
            byte[] result = super.getAuthenticationText();
            log.info("getAuthenticationText -> " + (result == null ? result : Hex.encodeHexString(result)));
            return result;
        }
    }
}