package sasl.xmpp.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jivesoftware.smack.ConnectionListener;
import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.spark.SparkManager;
import org.jivesoftware.spark.plugin.Invokable;
import org.jivesoftware.spark.plugin.Plugin;
import sasl.mechanism.did.DIDChallengeSaslProvider;
import sasl.xmpp.client.debug.SaslClientDebug;

import javax.swing.*;
import java.security.Security;
import java.util.Arrays;

public class DIDChallengeSaslPlugin implements Plugin, Invokable, ConnectionListener {

    private static final Logger log = LogManager.getLogger(DIDChallengeSaslPlugin.class);

    static {
        Security.addProvider(new DIDChallengeSaslProvider());
    }

    static {
        SaslClientDebug.logSaslClientFactoriesAndMechanisms();
    }

    @Override
    public void initialize() {
        log.debug("initialize");
        SASLAuthentication.unregisterSASLMechanism(SASLDIDChallengeJavaXMechanism.class.getName());
        SASLAuthentication.registerSASLMechanism(new SASLDIDChallengeJavaXMechanism(true));
        log.debug("SASL mechanisms: " + SASLAuthentication.getRegisterdSASLMechanisms());
        SparkManager.getConnection().addConnectionListener(this);
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
}