import org.apache.commons.io.IOUtils;
import org.apache.directory.server.core.authn.AuthenticationInterceptor;
import org.apache.directory.server.core.exception.ExceptionInterceptor;
import org.apache.directory.server.core.interceptor.Interceptor;
import org.apache.directory.server.core.normalization.NormalizationInterceptor;
import org.apache.directory.server.core.operational.OperationalAttributeInterceptor;
import org.apache.directory.server.core.referral.ReferralInterceptor;
import org.apache.directory.server.core.schema.SchemaInterceptor;
import org.apache.directory.server.core.subtree.SubentryInterceptor;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextMapper;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.server.ApacheDSContainer;

import javax.naming.directory.SearchControls;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by denyska on 9/16/16.
 */
public class TestMockLDAP
{
  private static final String ROOT = "dc=corp,dc=megacorp,dc=com";
  public static final int LDAP_PORT = 8389;
  public static final String LDAP_URL = "ldap://127.0.0.1:" + LDAP_PORT + "/";


  @Before
  public void setup() throws Exception
  {
    final String ldifResource = "classpath*:mock-ldap-server.ldif";

    final Resource[] ldifs = new PathMatchingResourcePatternResolver().getResources(ldifResource);

    final File temp = File.createTempFile("temp", ".ldif");
    temp.deleteOnExit();
    IOUtils.copy(ldifs[0].getInputStream(), new FileOutputStream(temp));
    final String tempLdifFilePath = "file:" + temp.getAbsolutePath();
    ApacheDSContainer apacheDsContainer = new ApacheDSContainer(ROOT, tempLdifFilePath);


    // see http://stackoverflow.com/questions/23474451/sample-active-directory-ldif-file-with-apacheds
    final List<Interceptor> list = new ArrayList<>();

    list.add(new NormalizationInterceptor());
    list.add(new AuthenticationInterceptor());
    list.add(new ReferralInterceptor());
    list.add(new ExceptionInterceptor());
    list.add(new OperationalAttributeInterceptor());
    list.add(new SchemaInterceptor());
    list.add(new SubentryInterceptor());


    apacheDsContainer.getService().setInterceptors(list);


    apacheDsContainer.setPort(LDAP_PORT);
    apacheDsContainer.afterPropertiesSet();
  }

  @Test
  public void testConnection() throws Exception
  {
    final DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(LDAP_URL);
    contextSource.afterPropertiesSet();

    final SearchControls searchControls = new SearchControls();
    searchControls.setCountLimit(1);
    searchControls.setTimeLimit(500);

    final LdapTemplate ldapTemplate = new SpringSecurityLdapTemplate(contextSource);
    ldapTemplate.setIgnoreNameNotFoundException(true);
    final Object userDN = ldapTemplate.searchForObject(
        "ou=my_users,DC=corp,DC=megacorp,DC=com",
        "(&(objectClass=user)(samAccountName=denyska))", new AbstractContextMapper()
        {
          @Override
          protected Object doMapFromContext(DirContextOperations ctx)
          {
            return ctx.getDn();
          }
        });

    System.out.println("USER: " + userDN);

    queryGroups(searchControls, ldapTemplate, "(&(objectClass=group)(cn=group1-*)(member=" + userDN + "))");

    System.out.println("________");
    queryGroups(searchControls, ldapTemplate, "(&(objectClass=group)(cn=group2*)(member=" + userDN + "))");
  }

  private void queryGroups(SearchControls searchControls, LdapTemplate ldapTemplate, String query)
  {
    ldapTemplate.search(
        "ou=my_groups,DC=corp,DC=megacorp,DC=com",
        query,
        searchControls,
        nameClassPair ->
        {
          System.out.println(nameClassPair);
        });
  }
}
