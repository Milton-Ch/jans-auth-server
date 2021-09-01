package io.jans.as.server.service;

import io.jans.as.model.config.StaticConfiguration;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.persistence.model.Scope;
import io.jans.orm.PersistenceEntryManager;
import io.jans.service.CacheService;
import io.jans.service.LocalCacheService;
import org.jboss.weld.junit.MockBean;
import org.jboss.weld.junit5.WeldInitiator;
import org.jboss.weld.junit5.WeldJunit5Extension;
import org.jboss.weld.junit5.WeldSetup;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;

import javax.enterprise.inject.spi.Bean;
import javax.inject.Inject;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.*;

@ExtendWith(WeldJunit5Extension.class)
public class ScopeServiceTest {

    @WeldSetup
    public WeldInitiator weld = WeldInitiator.from(ScopeService.class, ScopeServiceTest.class)
            .addBeans(buildBeans())
            .build();

    private static Bean<?>[] buildBeans() {
        return new Bean[] {
                MockBean.of(mock(AppConfiguration.class), AppConfiguration.class),
                MockBean.of(mock(StaticConfiguration.class), StaticConfiguration.class),
                MockBean.of(mock(LocalCacheService.class), LocalCacheService.class),
                MockBean.of(mock(CacheService.class), CacheService.class),
                MockBean.of(mock(PersistenceEntryManager.class), PersistenceEntryManager.class),
                MockBean.of(mock(Logger.class), Logger.class),
        };
    }

    @Inject
    private Logger log;

    @Inject
    private ScopeService scopeService;

    @Inject
    private AppConfiguration appConfiguration;

    @Test
    public void getScopeById() {
        when(appConfiguration.getUseLocalCache()).thenReturn(true);

        Scope result = scopeService.getScopeById("fake");

        assertNull(result);

        verify(appConfiguration).getUseLocalCache();
        verify(log).error(startsWith("Failed to find scope with id: "), any(Exception.class));

        verifyNoMoreInteractions(appConfiguration, log);
    }
}
