//package com.cloud.tv.core.utils.httpclient;
//
//import org.springframework.core.ParameterizedTypeReference;
//import org.springframework.core.SpringProperties;
//import org.springframework.httpclient.*;
//import org.springframework.httpclient.client.ClientHttpRequest;
//import org.springframework.httpclient.client.ClientHttpRequestFactory;
//import org.springframework.httpclient.client.ClientHttpResponse;
//import org.springframework.httpclient.converter.*;
//import org.springframework.httpclient.converter.cbor.MappingJackson2CborHttpMessageConverter;
//import org.springframework.httpclient.converter.feed.AtomFeedHttpMessageConverter;
//import org.springframework.httpclient.converter.feed.RssChannelHttpMessageConverter;
//import org.springframework.httpclient.converter.json.GsonHttpMessageConverter;
//import org.springframework.httpclient.converter.json.JsonbHttpMessageConverter;
//import org.springframework.httpclient.converter.json.KotlinSerializationJsonHttpMessageConverter;
//import org.springframework.httpclient.converter.json.MappingJackson2HttpMessageConverter;
//import org.springframework.httpclient.converter.smile.MappingJackson2SmileHttpMessageConverter;
//import org.springframework.httpclient.converter.support.AllEncompassingFormHttpMessageConverter;
//import org.springframework.httpclient.converter.xml.Jaxb2RootElementHttpMessageConverter;
//import org.springframework.httpclient.converter.xml.MappingJackson2XmlHttpMessageConverter;
//import org.springframework.httpclient.converter.xml.SourceHttpMessageConverter;
//import org.springframework.lang.Nullable;
//import org.springframework.util.Assert;
//import org.springframework.util.ClassUtils;
//import org.springframework.web.client.*;
//import org.springframework.web.util.AbstractUriTemplateHandler;
//import org.springframework.web.util.DefaultUriBuilderFactory;
//import org.springframework.web.util.UriTemplateHandler;
//
//import java.io.IOException;
//import java.lang.reflect.ParameterizedType;
//import java.lang.reflect.Type;
//import java.network.URI;
//import java.util.*;
//import java.util.stream.Collectors;
//import java.util.stream.Stream;
//
//public class MyRestTemplate extends RestTemplate {
//    private static final boolean shouldIgnoreXml = SpringProperties.getFlag("spring.xml.ignore");
//    private static final boolean romePresent;
//    private static final boolean jaxb2Present;
//    private static final boolean jackson2Present;
//    private static final boolean jackson2XmlPresent;
//    private static final boolean jackson2SmilePresent;
//    private static final boolean jackson2CborPresent;
//    private static final boolean gsonPresent;
//    private static final boolean jsonbPresent;
//    private static final boolean kotlinSerializationJsonPresent;
//    private final List<HttpMessageConverter<?>> messageConverters;
//    private ResponseErrorHandler errorHandler;
//    private UriTemplateHandler uriTemplateHandler;
//    private final ResponseExtractor<HttpHeaders> headersExtractor;
//
//    public MyRestTemplate() {
//        this.messageConverters = new ArrayList();
//        this.errorHandler = new DefaultResponseErrorHandler();
//        this.headersExtractor = new MyRestTemplate.HeadersExtractor();
//        this.messageConverters.add(new ByteArrayHttpMessageConverter());
//        this.messageConverters.add(new StringHttpMessageConverter());
//        this.messageConverters.add(new ResourceHttpMessageConverter(false));
//        if (!shouldIgnoreXml) {
//            try {
//                this.messageConverters.add(new SourceHttpMessageConverter());
//            } catch (Error var2) {
//                ;
//            }
//        }
//
//        this.messageConverters.add(new AllEncompassingFormHttpMessageConverter());
//        if (romePresent) {
//            this.messageConverters.add(new AtomFeedHttpMessageConverter());
//            this.messageConverters.add(new RssChannelHttpMessageConverter());
//        }
//
//        if (!shouldIgnoreXml) {
//            if (jackson2XmlPresent) {
//                this.messageConverters.add(new MappingJackson2XmlHttpMessageConverter());
//            } else if (jaxb2Present) {
//                this.messageConverters.add(new Jaxb2RootElementHttpMessageConverter());
//            }
//        }
//
//        if (jackson2Present) {
//            this.messageConverters.add(new MappingJackson2HttpMessageConverter());
//        } else if (gsonPresent) {
//            this.messageConverters.add(new GsonHttpMessageConverter());
//        } else if (jsonbPresent) {
//            this.messageConverters.add(new JsonbHttpMessageConverter());
//        } else if (kotlinSerializationJsonPresent) {
//            this.messageConverters.add(new KotlinSerializationJsonHttpMessageConverter());
//        }
//
//        if (jackson2SmilePresent) {
//            this.messageConverters.add(new MappingJackson2SmileHttpMessageConverter());
//        }
//
//        if (jackson2CborPresent) {
//            this.messageConverters.add(new MappingJackson2CborHttpMessageConverter());
//        }
//
//        this.uriTemplateHandler = initUriTemplateHandler();
//    }
//
//    public MyRestTemplate(ClientHttpRequestFactory requestFactory) {
//        this();
//        this.setRequestFactory(requestFactory);
//    }
//
//    public MyRestTemplate(List<HttpMessageConverter<?>> messageConverters) {
//        this.messageConverters = new ArrayList();
//        this.errorHandler = new DefaultResponseErrorHandler();
//        this.headersExtractor = new MyRestTemplate.HeadersExtractor();
//        this.validateConverters(messageConverters);
//        this.messageConverters.addAll(messageConverters);
//        this.uriTemplateHandler = initUriTemplateHandler();
//    }
//
//    private static DefaultUriBuilderFactory initUriTemplateHandler() {
//        DefaultUriBuilderFactory uriFactory = new DefaultUriBuilderFactory();
//        uriFactory.setEncodingMode(DefaultUriBuilderFactory.EncodingMode.URI_COMPONENT);
//        return uriFactory;
//    }
//
//    public void setMessageConverters(List<HttpMessageConverter<?>> messageConverters) {
//        this.validateConverters(messageConverters);
//        if (this.messageConverters != messageConverters) {
//            this.messageConverters.clear();
//            this.messageConverters.addAll(messageConverters);
//        }
//
//    }
//
//    private void validateConverters(List<HttpMessageConverter<?>> messageConverters) {
//        Assert.notEmpty(messageConverters, "At least one HttpMessageConverter is required");
//        Assert.noNullElements(messageConverters, "The HttpMessageConverter list must not contain null elements");
//    }
//
//    public List<HttpMessageConverter<?>> getMessageConverters() {
//        return this.messageConverters;
//    }
//
//    public void setErrorHandler(ResponseErrorHandler errorHandler) {
//        Assert.notNull(errorHandler, "ResponseErrorHandler must not be null");
//        this.errorHandler = errorHandler;
//    }
//
//    public ResponseErrorHandler getErrorHandler() {
//        return this.errorHandler;
//    }
//
//    public void setDefaultUriVariables(Map<String, ?> uriVars) {
//        if (this.uriTemplateHandler instanceof DefaultUriBuilderFactory) {
//            ((DefaultUriBuilderFactory)this.uriTemplateHandler).setDefaultUriVariables(uriVars);
//        } else {
//            if (!(this.uriTemplateHandler instanceof AbstractUriTemplateHandler)) {
//                throw new IllegalArgumentException("This property is not supported with the configured UriTemplateHandler.");
//            }
//
//            ((AbstractUriTemplateHandler)this.uriTemplateHandler).setDefaultUriVariables(uriVars);
//        }
//
//    }
//
//    public void setUriTemplateHandler(UriTemplateHandler handler) {
//        Assert.notNull(handler, "UriTemplateHandler must not be null");
//        this.uriTemplateHandler = handler;
//    }
//
//    public UriTemplateHandler getUriTemplateHandler() {
//        return this.uriTemplateHandler;
//    }
//
//    @Nullable
//    public <T> T getForObject(String url, Class<T> responseType, Object... uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.acceptHeaderRequestCallback(responseType);
//        HttpMessageConverterExtractor<T> responseExtractor = new HttpMessageConverterExtractor(responseType, this.getMessageConverters(), this.logger);
//        return this.execute(url, HttpMethod.GET, requestCallback, responseExtractor, (Object[])uriVariables);
//    }
//
//    @Nullable
//    public <T> T getForObject(String url, Class<T> responseType, Map<String, ?> uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.acceptHeaderRequestCallback(responseType);
//        HttpMessageConverterExtractor<T> responseExtractor = new HttpMessageConverterExtractor(responseType, this.getMessageConverters(), this.logger);
//        return this.execute(url, HttpMethod.GET, requestCallback, responseExtractor, (Map)uriVariables);
//    }
//
//    @Nullable
//    public <T> T getForObject(URI url, Class<T> responseType) throws RestClientException {
//        RequestCallback requestCallback = this.acceptHeaderRequestCallback(responseType);
//        HttpMessageConverterExtractor<T> responseExtractor = new HttpMessageConverterExtractor(responseType, this.getMessageConverters(), this.logger);
//        return this.execute(url, HttpMethod.GET, requestCallback, responseExtractor);
//    }
//
//    public <T> ResponseEntity<T> getForEntity(String url, Class<T> responseType, Object... uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.acceptHeaderRequestCallback(responseType);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(responseType);
//        return (ResponseEntity)nonNull(this.execute(url, HttpMethod.GET, requestCallback, responseExtractor, uriVariables));
//    }
//
//    public <T> ResponseEntity<T> getForEntity(String url, Class<T> responseType, Map<String, ?> uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.acceptHeaderRequestCallback(responseType);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(responseType);
//        return (ResponseEntity)nonNull(this.execute(url, HttpMethod.GET, requestCallback, responseExtractor, uriVariables));
//    }
//
//    public <T> ResponseEntity<T> getForEntity(URI url, Class<T> responseType) throws RestClientException {
//        RequestCallback requestCallback = this.acceptHeaderRequestCallback(responseType);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(responseType);
//        return (ResponseEntity)nonNull(this.execute(url, HttpMethod.GET, requestCallback, responseExtractor));
//    }
//
//    public HttpHeaders headForHeaders(String url, Object... uriVariables) throws RestClientException {
//        return (HttpHeaders)nonNull(this.execute(url, HttpMethod.HEAD, (RequestCallback)null, this.headersExtractor(), (Object[])uriVariables));
//    }
//
//    public HttpHeaders headForHeaders(String url, Map<String, ?> uriVariables) throws RestClientException {
//        return (HttpHeaders)nonNull(this.execute(url, HttpMethod.HEAD, (RequestCallback)null, this.headersExtractor(), (Map)uriVariables));
//    }
//
//    public HttpHeaders headForHeaders(URI url) throws RestClientException {
//        return (HttpHeaders)nonNull(this.execute(url, HttpMethod.HEAD, (RequestCallback)null, this.headersExtractor()));
//    }
//
//    @Nullable
//    public URI postForLocation(String url, @Nullable Object request, Object... uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request);
//        HttpHeaders headers = (HttpHeaders)this.execute(url, HttpMethod.POST, requestCallback, this.headersExtractor(), uriVariables);
//        return headers != null ? headers.getLocation() : null;
//    }
//
//    @Nullable
//    public URI postForLocation(String url, @Nullable Object request, Map<String, ?> uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request);
//        HttpHeaders headers = (HttpHeaders)this.execute(url, HttpMethod.POST, requestCallback, this.headersExtractor(), uriVariables);
//        return headers != null ? headers.getLocation() : null;
//    }
//
//    @Nullable
//    public URI postForLocation(URI url, @Nullable Object request) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request);
//        HttpHeaders headers = (HttpHeaders)this.execute(url, HttpMethod.POST, requestCallback, this.headersExtractor());
//        return headers != null ? headers.getLocation() : null;
//    }
//
//    @Nullable
//    public <T> T postForObject(String url, @Nullable Object request, Class<T> responseType, Object... uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request, responseType);
//        HttpMessageConverterExtractor<T> responseExtractor = new HttpMessageConverterExtractor(responseType, this.getMessageConverters(), this.logger);
//        return this.execute(url, HttpMethod.POST, requestCallback, responseExtractor, (Object[])uriVariables);
//    }
//
//    @Nullable
//    public <T> T postForObject(String url, @Nullable Object request, Class<T> responseType, Map<String, ?> uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request, responseType);
//        HttpMessageConverterExtractor<T> responseExtractor = new HttpMessageConverterExtractor(responseType, this.getMessageConverters(), this.logger);
//        return this.execute(url, HttpMethod.POST, requestCallback, responseExtractor, (Map)uriVariables);
//    }
//
//    @Nullable
//    public <T> T postForObject(URI url, @Nullable Object request, Class<T> responseType) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request, responseType);
//        HttpMessageConverterExtractor<T> responseExtractor = new HttpMessageConverterExtractor(responseType, this.getMessageConverters());
//        return this.execute(url, HttpMethod.POST, requestCallback, responseExtractor);
//    }
//
//    public <T> ResponseEntity<T> postForEntity(String url, @Nullable Object request, Class<T> responseType, Object... uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request, responseType);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(responseType);
//        return (ResponseEntity)nonNull(this.execute(url, HttpMethod.POST, requestCallback, responseExtractor, uriVariables));
//    }
//
//    public <T> ResponseEntity<T> postForEntity(String url, @Nullable Object request, Class<T> responseType, Map<String, ?> uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request, responseType);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(responseType);
//        return (ResponseEntity)nonNull(this.execute(url, HttpMethod.POST, requestCallback, responseExtractor, uriVariables));
//    }
//
//    public <T> ResponseEntity<T> postForEntity(URI url, @Nullable Object request, Class<T> responseType) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request, responseType);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(responseType);
//        return (ResponseEntity)nonNull(this.execute(url, HttpMethod.POST, requestCallback, responseExtractor));
//    }
//
//    public void put(String url, @Nullable Object request, Object... uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request);
//        this.execute(url, HttpMethod.PUT, requestCallback, (ResponseExtractor)null, (Object[])uriVariables);
//    }
//
//    public void put(String url, @Nullable Object request, Map<String, ?> uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request);
//        this.execute(url, HttpMethod.PUT, requestCallback, (ResponseExtractor)null, (Map)uriVariables);
//    }
//
//    public void put(URI url, @Nullable Object request) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request);
//        this.execute(url, HttpMethod.PUT, requestCallback, (ResponseExtractor)null);
//    }
//
//    @Nullable
//    public <T> T patchForObject(String url, @Nullable Object request, Class<T> responseType, Object... uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request, responseType);
//        HttpMessageConverterExtractor<T> responseExtractor = new HttpMessageConverterExtractor(responseType, this.getMessageConverters(), this.logger);
//        return this.execute(url, HttpMethod.PATCH, requestCallback, responseExtractor, (Object[])uriVariables);
//    }
//
//    @Nullable
//    public <T> T patchForObject(String url, @Nullable Object request, Class<T> responseType, Map<String, ?> uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request, responseType);
//        HttpMessageConverterExtractor<T> responseExtractor = new HttpMessageConverterExtractor(responseType, this.getMessageConverters(), this.logger);
//        return this.execute(url, HttpMethod.PATCH, requestCallback, responseExtractor, (Map)uriVariables);
//    }
//
//    @Nullable
//    public <T> T patchForObject(URI url, @Nullable Object request, Class<T> responseType) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(request, responseType);
//        HttpMessageConverterExtractor<T> responseExtractor = new HttpMessageConverterExtractor(responseType, this.getMessageConverters());
//        return this.execute(url, HttpMethod.PATCH, requestCallback, responseExtractor);
//    }
//
//    public void delete(String url, Object... uriVariables) throws RestClientException {
//        this.execute(url, HttpMethod.DELETE, (RequestCallback)null, (ResponseExtractor)null, (Object[])uriVariables);
//    }
//
//    public void delete(String url, Map<String, ?> uriVariables) throws RestClientException {
//        this.execute(url, HttpMethod.DELETE, (RequestCallback)null, (ResponseExtractor)null, (Map)uriVariables);
//    }
//
//    public void delete(URI url) throws RestClientException {
//        this.execute(url, HttpMethod.DELETE, (RequestCallback)null, (ResponseExtractor)null);
//    }
//
//    public Set<HttpMethod> optionsForAllow(String url, Object... uriVariables) throws RestClientException {
//        ResponseExtractor<HttpHeaders> headersExtractor = this.headersExtractor();
//        HttpHeaders headers = (HttpHeaders)this.execute(url, HttpMethod.OPTIONS, (RequestCallback)null, headersExtractor, (Object[])uriVariables);
//        return headers != null ? headers.getAllow() : Collections.emptySet();
//    }
//
//    public Set<HttpMethod> optionsForAllow(String url, Map<String, ?> uriVariables) throws RestClientException {
//        ResponseExtractor<HttpHeaders> headersExtractor = this.headersExtractor();
//        HttpHeaders headers = (HttpHeaders)this.execute(url, HttpMethod.OPTIONS, (RequestCallback)null, headersExtractor, (Map)uriVariables);
//        return headers != null ? headers.getAllow() : Collections.emptySet();
//    }
//
//    public Set<HttpMethod> optionsForAllow(URI url) throws RestClientException {
//        ResponseExtractor<HttpHeaders> headersExtractor = this.headersExtractor();
//        HttpHeaders headers = (HttpHeaders)this.execute(url, HttpMethod.OPTIONS, (RequestCallback)null, headersExtractor);
//        return headers != null ? headers.getAllow() : Collections.emptySet();
//    }
//
//    public <T> ResponseEntity<T> exchange(String url, HttpMethod method, @Nullable HttpEntity<?> requestEntity, Class<T> responseType, Object... uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(requestEntity, responseType);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(responseType);
//        return (ResponseEntity)nonNull(this.execute(url, method, requestCallback, responseExtractor, uriVariables));
//    }
//
//    public <T> ResponseEntity<T> exchange(String url, HttpMethod method, @Nullable HttpEntity<?> requestEntity, Class<T> responseType, Map<String, ?> uriVariables) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(requestEntity, responseType);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(responseType);
//        return (ResponseEntity)nonNull(this.execute(url, method, requestCallback, responseExtractor, uriVariables));
//    }
//
//    public <T> ResponseEntity<T> exchange(URI url, HttpMethod method, @Nullable HttpEntity<?> requestEntity, Class<T> responseType) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(requestEntity, responseType);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(responseType);
//        return (ResponseEntity)nonNull(this.execute(url, method, requestCallback, responseExtractor));
//    }
//
//    public <T> ResponseEntity<T> exchange(String url, HttpMethod method, @Nullable HttpEntity<?> requestEntity, ParameterizedTypeReference<T> responseType, Object... uriVariables) throws RestClientException {
//        Type type = responseType.getType();
//        RequestCallback requestCallback = this.httpEntityCallback(requestEntity, type);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(type);
//        return (ResponseEntity)nonNull(this.execute(url, method, requestCallback, responseExtractor, uriVariables));
//    }
//
//    public <T> ResponseEntity<T> exchange(String url, HttpMethod method, @Nullable HttpEntity<?> requestEntity, ParameterizedTypeReference<T> responseType, Map<String, ?> uriVariables) throws RestClientException {
//        Type type = responseType.getType();
//        RequestCallback requestCallback = this.httpEntityCallback(requestEntity, type);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(type);
//        return (ResponseEntity)nonNull(this.execute(url, method, requestCallback, responseExtractor, uriVariables));
//    }
//
//    public <T> ResponseEntity<T> exchange(URI url, HttpMethod method, @Nullable HttpEntity<?> requestEntity, ParameterizedTypeReference<T> responseType) throws RestClientException {
//        Type type = responseType.getType();
//        RequestCallback requestCallback = this.httpEntityCallback(requestEntity, type);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(type);
//        return (ResponseEntity)nonNull(this.execute(url, method, requestCallback, responseExtractor));
//    }
//
//    public <T> ResponseEntity<T> exchange(RequestEntity<?> entity, Class<T> responseType) throws RestClientException {
//        RequestCallback requestCallback = this.httpEntityCallback(entity, responseType);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(responseType);
//        return (ResponseEntity)nonNull(this.doExecute(this.resolveUrl(entity), entity.getMethod(), requestCallback, responseExtractor));
//    }
//
//    public <T> ResponseEntity<T> exchange(RequestEntity<?> entity, ParameterizedTypeReference<T> responseType) throws RestClientException {
//        Type type = responseType.getType();
//        RequestCallback requestCallback = this.httpEntityCallback(entity, type);
//        ResponseExtractor<ResponseEntity<T>> responseExtractor = this.responseEntityExtractor(type);
//        return (ResponseEntity)nonNull(this.doExecute(this.resolveUrl(entity), entity.getMethod(), requestCallback, responseExtractor));
//    }
//
//    private URI resolveUrl(RequestEntity<?> entity) {
//        if (entity instanceof UriTemplateRequestEntity) {
//            UriTemplateRequestEntity<?> ext = (UriTemplateRequestEntity)entity;
//            if (ext.getVars() != null) {
//                return this.uriTemplateHandler.expand(ext.getUriTemplate(), ext.getVars());
//            } else if (ext.getVarsMap() != null) {
//                return this.uriTemplateHandler.expand(ext.getUriTemplate(), ext.getVarsMap());
//            } else {
//                throw new IllegalStateException("No variables specified for URI templates: " + ext.getUriTemplate());
//            }
//        } else {
//            return entity.getUrl();
//        }
//    }
//
//    @Nullable
//    public <T> T execute(String url, HttpMethod method, @Nullable RequestCallback requestCallback, @Nullable ResponseExtractor<T> responseExtractor, Object... uriVariables) throws RestClientException {
//        URI expanded = this.getUriTemplateHandler().expand(url, uriVariables);
//        return this.doExecute(expanded, method, requestCallback, responseExtractor);
//    }
//
//    @Nullable
//    public <T> T execute(String url, HttpMethod method, @Nullable RequestCallback requestCallback, @Nullable ResponseExtractor<T> responseExtractor, Map<String, ?> uriVariables) throws RestClientException {
//        URI expanded = this.getUriTemplateHandler().expand(url, uriVariables);
//        return this.doExecute(expanded, method, requestCallback, responseExtractor);
//    }
//
//    @Nullable
//    public <T> T execute(URI url, HttpMethod method, @Nullable RequestCallback requestCallback, @Nullable ResponseExtractor<T> responseExtractor) throws RestClientException {
//        return this.doExecute(url, method, requestCallback, responseExtractor);
//    }
//
//    @Nullable
//    protected <T> T doExecute(URI url, @Nullable HttpMethod method, @Nullable RequestCallback requestCallback, @Nullable ResponseExtractor<T> responseExtractor) throws RestClientException {
//        Assert.notNull(url, "URI is required");
//        Assert.notNull(method, "HttpMethod is required");
//        ClientHttpResponse response = null;
//
//        Object var14;
//        try {
//            ClientHttpRequest request = this.createRequest(url, method);
//            if (requestCallback != null) {
//                requestCallback.doWithRequest(request);
//            }
//
//            response = request.execute();
//            this.handleResponse(url, method, response);
//            var14 = responseExtractor != null ? responseExtractor.extractData(response) : null;
//        } catch (IOException var12) {
//            String resource = url.toString();
//            String query = url.getRawQuery();
//            resource = query != null ? resource.substring(0, resource.indexOf(63)) : resource;
//            throw new ResourceAccessException("I/O error on " + method.name() + " request for \"" + resource + "\": " + var12.getMessage(), var12);
//        } finally {
//            if (response != null) {
//                response.close();
//            }
//
//        }
//
//        return var14;
//    }
//
//    protected void handleResponse(URI url, HttpMethod method, ClientHttpResponse response) throws IOException {
//        ResponseErrorHandler errorHandler = this.getErrorHandler();
//        boolean hasError = errorHandler.hasError(response);
//        if (this.logger.isDebugEnabled()) {
//            try {
//                int code = response.getRawStatusCode();
//                HttpStatus status = HttpStatus.resolve(code);
//                this.logger.debug("Response " + (status != null ? status : code));
//            } catch (IOException var8) {
//                ;
//            }
//        }
//
//        if (hasError) {
//            errorHandler.handleError(url, method, response);
//        }
//
//    }
//
//    public <T> RequestCallback acceptHeaderRequestCallback(Class<T> responseType) {
//        return new RestTemplate.AcceptHeaderRequestCallback(responseType);
//    }
//
//    public <T> RequestCallback httpEntityCallback(@Nullable Object requestBody) {
//        return new RestTemplate.HttpEntityRequestCallback(requestBody);
//    }
//
//    public <T> RequestCallback httpEntityCallback(@Nullable Object requestBody, Type responseType) {
//        return new RestTemplate.HttpEntityRequestCallback(requestBody, responseType);
//    }
//
//    public <T> ResponseExtractor<ResponseEntity<T>> responseEntityExtractor(Type responseType) {
//        return new RestTemplate.ResponseEntityResponseExtractor(responseType);
//    }
//
//    protected ResponseExtractor<HttpHeaders> headersExtractor() {
//        return this.headersExtractor;
//    }
//
//    private static <T> T nonNull(@Nullable T result) {
//        Assert.state(result != null, "No result");
//        return result;
//    }
//
//    static {
//        ClassLoader classLoader = RestTemplate.class.getClassLoader();
//        romePresent = ClassUtils.isPresent("com.rometools.rome.feed.WireFeed", classLoader);
//        jaxb2Present = ClassUtils.isPresent("javax.xml.bind.Binder", classLoader);
//        jackson2Present = ClassUtils.isPresent("com.fasterxml.jackson.databind.ObjectMapper", classLoader) && ClassUtils.isPresent("com.fasterxml.jackson.core.JsonGenerator", classLoader);
//        jackson2XmlPresent = ClassUtils.isPresent("com.fasterxml.jackson.dataformat.xml.XmlMapper", classLoader);
//        jackson2SmilePresent = ClassUtils.isPresent("com.fasterxml.jackson.dataformat.smile.SmileFactory", classLoader);
//        jackson2CborPresent = ClassUtils.isPresent("com.fasterxml.jackson.dataformat.cbor.CBORFactory", classLoader);
//        gsonPresent = ClassUtils.isPresent("com.google.gson.Gson", classLoader);
//        jsonbPresent = ClassUtils.isPresent("javax.json.bind.Jsonb", classLoader);
//        kotlinSerializationJsonPresent = ClassUtils.isPresent("kotlinx.serialization.json.Json", classLoader);
//    }
//
//    private static class HeadersExtractor implements ResponseExtractor<HttpHeaders> {
//        private HeadersExtractor() {
//        }
//
//        public HttpHeaders extractData(ClientHttpResponse response) {
//            return response.getHeaders();
//        }
//    }
//
//    private class ResponseEntityResponseExtractor<T> implements ResponseExtractor<ResponseEntity<T>> {
//        @Nullable
//        private final HttpMessageConverterExtractor<T> delegate;
//
//        public ResponseEntityResponseExtractor(@Nullable Type responseType) {
//            if (responseType != null && Void.class != responseType) {
//                this.delegate = new HttpMessageConverterExtractor(responseType, RestTemplate.this.getMessageConverters(), RestTemplate.this.logger);
//            } else {
//                this.delegate = null;
//            }
//
//        }
//
//        public ResponseEntity<T> extractData(ClientHttpResponse response) throws IOException {
//            if (this.delegate != null) {
//                T body = this.delegate.extractData(response);
//                return ((ResponseEntity.BodyBuilder)ResponseEntity.status(response.getRawStatusCode()).headers(response.getHeaders())).body(body);
//            } else {
//                return ((ResponseEntity.BodyBuilder)ResponseEntity.status(response.getRawStatusCode()).headers(response.getHeaders())).build();
//            }
//        }
//    }
//
//    private class HttpEntityRequestCallback extends RestTemplate.AcceptHeaderRequestCallback {
//        private final HttpEntity<?> requestEntity;
//
//        public HttpEntityRequestCallback(@Nullable Object requestBody) {
//            this(requestBody, (Type)null);
//        }
//
//        public HttpEntityRequestCallback(@Nullable Object requestBody, @Nullable Type responseType) {
//            super(responseType);
//            if (requestBody instanceof HttpEntity) {
//                this.requestEntity = (HttpEntity)requestBody;
//            } else if (requestBody != null) {
//                this.requestEntity = new HttpEntity(requestBody);
//            } else {
//                this.requestEntity = HttpEntity.EMPTY;
//            }
//
//        }
//
//        public void doWithRequest(ClientHttpRequest httpRequest) throws IOException {
//            super.doWithRequest(httpRequest);
//            Object requestBody = this.requestEntity.getBody();
//            if (requestBody == null) {
//                HttpHeaders httpHeaders = httpRequest.getHeaders();
//                HttpHeaders requestHeaders = this.requestEntity.getHeaders();
//                if (!requestHeaders.isEmpty()) {
//                    requestHeaders.forEach((key, values) -> {
//                        httpHeaders.put(key, new ArrayList(values));
//                    });
//                }
//
//                if (httpHeaders.getContentLength() < 0L) {
//                    httpHeaders.setContentLength(0L);
//                }
//
//            } else {
//                Class<?> requestBodyClass = requestBody.getClass();
//                Type requestBodyType = this.requestEntity instanceof RequestEntity ? ((RequestEntity)this.requestEntity).getType() : requestBodyClass;
//                HttpHeaders httpHeadersx = httpRequest.getHeaders();
//                HttpHeaders requestHeadersx = this.requestEntity.getHeaders();
//                MediaType requestContentType = requestHeadersx.getContentType();
//                Iterator var8 = RestTemplate.this.getMessageConverters().iterator();
//
//                while(var8.hasNext()) {
//                    HttpMessageConverter<?> messageConverter = (HttpMessageConverter)var8.next();
//                    if (messageConverter instanceof GenericHttpMessageConverter) {
//                        GenericHttpMessageConverter<Object> genericConverter = (GenericHttpMessageConverter)messageConverter;
//                        if (genericConverter.canWrite((Type)requestBodyType, requestBodyClass, requestContentType)) {
//                            if (!requestHeadersx.isEmpty()) {
//                                requestHeadersx.forEach((key, values) -> {
//                                    httpHeadersx.put(key, new ArrayList(values));
//                                });
//                            }
//
//                            this.logBody(requestBody, requestContentType, genericConverter);
//                            genericConverter.write(requestBody, (Type)requestBodyType, requestContentType, httpRequest);
//                            return;
//                        }
//                    } else if (messageConverter.canWrite(requestBodyClass, requestContentType)) {
//                        if (!requestHeadersx.isEmpty()) {
//                            requestHeadersx.forEach((key, values) -> {
//                                httpHeadersx.put(key, new ArrayList(values));
//                            });
//                        }
//
//                        this.logBody(requestBody, requestContentType, messageConverter);
//                        messageConverter.write(requestBody, requestContentType, httpRequest);
//                        return;
//                    }
//                }
//
//                String message = "No HttpMessageConverter for " + requestBodyClass.getName();
//                if (requestContentType != null) {
//                    message = message + " and content type \"" + requestContentType + "\"";
//                }
//
//                throw new RestClientException(message);
//            }
//        }
//
//        private void logBody(Object body, @Nullable MediaType mediaType, HttpMessageConverter<?> converter) {
//            if (RestTemplate.this.logger.isDebugEnabled()) {
//                if (mediaType != null) {
//                    RestTemplate.this.logger.debug("Writing [" + body + "] as \"" + mediaType + "\"");
//                } else {
//                    RestTemplate.this.logger.debug("Writing [" + body + "] with " + converter.getClass().getName());
//                }
//            }
//
//        }
//    }
//
//    private class AcceptHeaderRequestCallback implements RequestCallback {
//        @Nullable
//        private final Type responseType;
//
//        public AcceptHeaderRequestCallback(@Nullable Type responseType) {
//            this.responseType = responseType;
//        }
//
//        public void doWithRequest(ClientHttpRequest request) throws IOException {
//            if (this.responseType != null) {
//                List<MediaType> allSupportedMediaTypes = (List)RestTemplate.this.getMessageConverters().stream().filter((converter) -> {
//                    return this.canReadResponse(this.responseType, converter);
//                }).flatMap((converter) -> {
//                    return this.getSupportedMediaTypes(this.responseType, converter);
//                }).distinct().sorted(MediaType.SPECIFICITY_COMPARATOR).collect(Collectors.toList());
//                if (RestTemplate.this.logger.isDebugEnabled()) {
//                    RestTemplate.this.logger.debug("Accept=" + allSupportedMediaTypes);
//                }
//
//                request.getHeaders().setAccept(allSupportedMediaTypes);
//            }
//
//        }
//
//        private boolean canReadResponse(Type responseType, HttpMessageConverter<?> converter) {
//            Class<?> responseClass = responseType instanceof Class ? (Class)responseType : null;
//            if (responseClass != null) {
//                return converter.canRead(responseClass, (MediaType)null);
//            } else if (converter instanceof GenericHttpMessageConverter) {
//                GenericHttpMessageConverter<?> genericConverter = (GenericHttpMessageConverter)converter;
//                return genericConverter.canRead(responseType, (Class)null, (MediaType)null);
//            } else {
//                return false;
//            }
//        }
//
//        private Stream<MediaType> getSupportedMediaTypes(Type type, HttpMessageConverter<?> converter) {
//            Type rawType = type instanceof ParameterizedType ? ((ParameterizedType)type).getRawType() : type;
//            Class<?> clazz = rawType instanceof Class ? (Class)rawType : null;
//            return (clazz != null ? converter.getSupportedMediaTypes(clazz) : converter.getSupportedMediaTypes()).stream().map((mediaType) -> {
//                return mediaType.getCharset() != null ? new MediaType(mediaType.getType(), mediaType.getSubtype()) : mediaType;
//            });
//        }
//    }
//
//}
