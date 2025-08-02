# evidence

The following hosts have been analyzed:

{% for asset in services.keys() %}
* `{{ asset }}`
{% endfor %}

The following vulnerabilities and/or deviations from the recommended settings (`{{recommendations_file}}`) have been identified:
{% for description, assets in issues|items %}

## {{ description }}

This issue has been found in the following assets:

{% for asset in assets %}
* `{{ asset }}`
{% endfor %}
{% endfor %}

# affected assets

{% for asset in affected_assets.keys() %}
* `{{ asset }}`
{% endfor %}
{% if recommendations|length %}

# recommendations

{% for recommendation in recommendations %}
* {{ recommendation }}
{% endfor %}
{% endif %}
{% if references|length %}

# references

{% for reference in references %}
* {{ reference }}
{% endfor %}
{% endif %}
{% if info|length %}

# additional info

{% for info in additional_info %}
* {{ info }}
{% endfor %}
{% endif %}
