// Hand-written for the importer's tests: the shape of the file that the
// importer reads the SOAP envelope from, with an envelope of its own.
package placeholder

import "net/http"

const soapBodyPayloadWrapper = `<Envelope xmlns="urn:fixture:envelope">
	<Body><%s>%s</%s></Body>
</Envelope>`

type SOAPBody struct{}

func (p *SOAPBody) prepareGoHTTPClientRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("SOAPAction", `"urn:fixture:action"`)
	req.Header.Add("Content-Type", "text/xml")
	return req, nil
}
