from django import forms

class CapturedDataForm(forms.Form):
    captured_data = forms.CharField(widget=forms.Textarea, required=True)