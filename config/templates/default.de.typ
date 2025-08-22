= evidenz

Die folgenden Hosts wurden analysiert:

{% for asset in services.keys() %}
- `{{ asset }}`
{% endfor %}

Die folgenden Schwachstellen und/oder Abweichungen von den empfohlenen Einstellungen (`{{recommendations_file}}`) wurden identifiziert:
{% for asset, issues in affected_assets.items() %}

== {{ asset }}

{% for issue in issues %}
- {{ issue }}
{% endfor %}
{% endfor %}

= betroffene assets

{% for asset in affected_assets.keys() %}
- `{{ asset }}`
{% endfor %}
{% if recommendations|length %}

= empfehlungen

{% for recommendation in recommendations %}
- {{ recommendation }}
{% endfor %}
{% endif %}
{% if references|length %}

= zusätzliche informationen

{% for reference in references %}
- {{ reference }}
{% endfor %}
{% endif %}
{% if additional_info|length %}

= additional info

{% for info in additional_info %}
- {{ info }}
{% endfor %}
{% endif %}