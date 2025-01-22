# evidenz

Die folgenden Hosts wurden analysiert:

{% for asset in services.keys() %}
* `{{ asset }}`
{% endfor %}

Die folgenden Schwachstellen und/oder Abweichungen von den empfohlenen Einstellungen (`{{recommendations_file}}`) wurden identifiziert:
{% for description, assets in issues|items %}

## {{ description }}

Dieser Sachverhalt wurde bei folgenden Assets festgestellt:

{% for asset in assets %}
* `{{ asset }}`
{% endfor %}
{% endfor %}

# betroffene assets

{% for asset in affected_assets.keys() %}
* `{{ asset }}`
{% endfor %}

{% if recommendations|length %}
# empfehlungen

{% for recommendation in recommendations %}
* {{ recommendation }}
{% endfor %}
{% endif %}

{% if references|length %}
# referenzen

{% for reference in references %}
* {{ reference }}
{% endfor %}
{% endif %}

{% if info|length %}
# zusätzliche informationen

{% for info in additional_info %}
* {{ info }}
{% endfor %}
{% endif %}
