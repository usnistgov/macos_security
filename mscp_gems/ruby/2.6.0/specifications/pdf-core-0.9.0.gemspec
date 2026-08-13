# -*- encoding: utf-8 -*-
# stub: pdf-core 0.9.0 ruby lib

Gem::Specification.new do |s|
  s.name = "pdf-core".freeze
  s.version = "0.9.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.3.6".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Gregory Brown".freeze, "Brad Ediger".freeze, "Daniel Nelson".freeze, "Jonathan Greenberg".freeze, "James Healy".freeze]
  s.cert_chain = ["-----BEGIN CERTIFICATE-----\nMIIDODCCAiCgAwIBAgIBATANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDDBhhbGV4\nL0RDPXBvaW50bGVzcy9EQz1vbmUwHhcNMjAwODAxMTQxMjE1WhcNMjEwODAxMTQx\nMjE1WjAjMSEwHwYDVQQDDBhhbGV4L0RDPXBvaW50bGVzcy9EQz1vbmUwggEiMA0G\nCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPOVLPGEK+eaP6zJfifrpWvPTg4qo3\nXNJJPom80SwqX2hVCVsRDK4RYgKUQqKRQzHhlx14wZHwWLETBVbNDGX3uqyCnTWU\nJUKh3ydiZShXpNHoV/NW7hhEYvNsDcBAjYTmbvXOhuYCo0Tz/0N2Oiun/0wIICtP\nvytY9TY0/lklWjAbsqJjNOu3o8IYkJBAN/rU96E/6WhFwjnxLcTnV9RfFRXdjG5j\nCughoB2xSwKX8gwbQ8fsnaZRmdyDGYNpz6sGF0zycfiLkTttbLA2nYATCALy98CH\nnsyZNsTjb4WINCuY2yEDjwesw9f/ROkNC68EgQ5M+aMjp+D0WcYGfzojAgMBAAGj\ndzB1MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgSwMB0GA1UdDgQWBBRPgIwSVbeonua/\nNy/8576oxdUbrjAdBgNVHREEFjAUgRJhbGV4QHBvaW50bGVzcy5vbmUwHQYDVR0S\nBBYwFIESYWxleEBwb2ludGxlc3Mub25lMA0GCSqGSIb3DQEBCwUAA4IBAQAzhGxF\nM0bXJ9GWD9vdVHOyzBQBJcJAvnsz2yV3+r4eJBsQynFIscsea8lHFL/d1eHYP0mN\nk0fhK+WDcPlrj0Sn/Ezhk2qogTIekwDOK6pZkGRQzD45leJqQMnYd+/TXK3ri485\nGi4oJ6NitnnUT59SQnjD5JcENfc0EcRzclmVRFE8W4O+ORgo4Dypq1rwYUzxeyUk\nmP5jNBWtH+hGUph28GQb0Hph6YnQb8zEFB88Xq80PK1SzkIPHpbTBk9mwPf6ypeX\nUn1TJEahAlgENVml6CyDXSwk0H8N1V3gm1mb9Fe1T2Z/kAzvjo0qTDEtMVLU7Bxh\nuqMUrdETjTnRYCVq\n-----END CERTIFICATE-----\n".freeze]
  s.date = "2020-10-24"
  s.description = "PDF::Core is used by Prawn to render PDF documents".freeze
  s.email = ["gregory.t.brown@gmail.com".freeze, "brad@bradediger.com".freeze, "dnelson@bluejade.com".freeze, "greenberg@entryway.net".freeze, "jimmy@deefa.com".freeze]
  s.homepage = "http://prawnpdf.org".freeze
  s.licenses = ["PRAWN".freeze, "GPL-2.0".freeze, "GPL-3.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.5".freeze)
  s.rubygems_version = "3.0.3.1".freeze
  s.summary = "PDF::Core is used by Prawn to render PDF documents".freeze

  s.installed_by_version = "3.0.3.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<pdf-inspector>.freeze, ["~> 1.1.0"])
      s.add_development_dependency(%q<pdf-reader>.freeze, ["~> 1.2"])
      s.add_development_dependency(%q<rake>.freeze, [">= 0"])
      s.add_development_dependency(%q<rspec>.freeze, [">= 0"])
      s.add_development_dependency(%q<rubocop>.freeze, ["~> 0.93"])
      s.add_development_dependency(%q<rubocop-performance>.freeze, ["~> 1.8"])
      s.add_development_dependency(%q<rubocop-rspec>.freeze, ["~> 1.44"])
      s.add_development_dependency(%q<simplecov>.freeze, [">= 0"])
    else
      s.add_dependency(%q<pdf-inspector>.freeze, ["~> 1.1.0"])
      s.add_dependency(%q<pdf-reader>.freeze, ["~> 1.2"])
      s.add_dependency(%q<rake>.freeze, [">= 0"])
      s.add_dependency(%q<rspec>.freeze, [">= 0"])
      s.add_dependency(%q<rubocop>.freeze, ["~> 0.93"])
      s.add_dependency(%q<rubocop-performance>.freeze, ["~> 1.8"])
      s.add_dependency(%q<rubocop-rspec>.freeze, ["~> 1.44"])
      s.add_dependency(%q<simplecov>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<pdf-inspector>.freeze, ["~> 1.1.0"])
    s.add_dependency(%q<pdf-reader>.freeze, ["~> 1.2"])
    s.add_dependency(%q<rake>.freeze, [">= 0"])
    s.add_dependency(%q<rspec>.freeze, [">= 0"])
    s.add_dependency(%q<rubocop>.freeze, ["~> 0.93"])
    s.add_dependency(%q<rubocop-performance>.freeze, ["~> 1.8"])
    s.add_dependency(%q<rubocop-rspec>.freeze, ["~> 1.44"])
    s.add_dependency(%q<simplecov>.freeze, [">= 0"])
  end
end
