FROM jenkins/jenkins:lts-jdk21

COPY --chown=jenkins:jenkins plugins.txt /usr/share/jenkins/ref/plugins.txt
COPY --chown=jenkins:jenkins init.groovy.d/ /usr/share/jenkins/ref/init.groovy.d/

RUN jenkins-plugin-cli -f /usr/share/jenkins/ref/plugins.txt
