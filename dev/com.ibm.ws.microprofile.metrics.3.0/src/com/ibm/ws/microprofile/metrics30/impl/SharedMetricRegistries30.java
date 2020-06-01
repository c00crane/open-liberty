/*******************************************************************************
 * Copyright (c) 2020 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.microprofile.metrics30.impl;

import org.eclipse.microprofile.config.spi.ConfigProviderResolver;
import org.eclipse.microprofile.metrics.MetricID;
import org.eclipse.microprofile.metrics.MetricRegistry;
import org.osgi.service.component.annotations.Component;

import com.ibm.ws.microprofile.metrics.impl.SharedMetricRegistries;

/**
 * A map of shared, named metric registries.
 */
@Component(service = SharedMetricRegistries.class, immediate = true)
public class SharedMetricRegistries30 extends SharedMetricRegistries {

    @Override
    protected MetricRegistry createNewMetricRegsitry(ConfigProviderResolver configResolver) {
        return new MetricRegistry30Impl(configResolver);
    }

    @Override
    public void associateMetricIDToApplication(MetricID metricID, String appName, MetricRegistry registry) {
        if (MetricRegistry30Impl.class.isInstance(registry)) {
            MetricRegistry30Impl metricRegistryImpl = (MetricRegistry30Impl) registry;
            metricRegistryImpl.addNameToApplicationMap(metricID, appName);
        }

    }

}
