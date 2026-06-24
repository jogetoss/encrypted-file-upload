package org.joget.marketplace;

import java.util.ArrayList;
import java.util.Collection;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;

public class Activator implements BundleActivator {

    public static final String VERSION = "9.0.0";

    protected Collection<ServiceRegistration> registrationList;

    public void start(BundleContext context) {
        registrationList = new ArrayList<ServiceRegistration>();

        registrationList.add(context.registerService(EncryptedFileUpload.class.getName(), new EncryptedFileUpload(), null));
        registrationList.add(context.registerService(EncryptedFileDatalistFormatter.class.getName(), new EncryptedFileDatalistFormatter(), null));
    }

    public void stop(BundleContext context) {
        for (ServiceRegistration registration : registrationList) {
            registration.unregister();
        }
    }
}
