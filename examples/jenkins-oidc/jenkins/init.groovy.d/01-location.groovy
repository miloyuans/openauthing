import jenkins.model.JenkinsLocationConfiguration

def jenkinsUrl = System.getenv('JENKINS_URL')
if (jenkinsUrl != null && !jenkinsUrl.trim().isEmpty()) {
  def config = JenkinsLocationConfiguration.get()
  config.setUrl(jenkinsUrl)
  config.save()
}
