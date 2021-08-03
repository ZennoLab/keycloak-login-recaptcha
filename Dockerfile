FROM altsgamerlab/keycloak-user-migration:latest

USER root

COPY . /project
RUN cd /project && chmod +x mvnw && ./mvnw clean install

FROM altsgamerlab/keycloak-user-migration:latest
USER root
COPY --from=0 /project/login.ftl /opt/jboss/keycloak/themes/base/login/login.ftl
COPY --from=0 /project/target/recaptcha-login.jar /opt/jboss/keycloak/standalone/deployments/recaptcha-login.jar

USER 1000