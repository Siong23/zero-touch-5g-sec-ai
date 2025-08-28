from django import forms

class CapturedDataForm(forms.Form):
    captured_data = forms.FileField(required=False)
    captured_text = forms.CharField(widget=forms.Textarea, required=False)