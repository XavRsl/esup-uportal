/**
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.jasig.portal.rendering;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.OutputKeys;

import org.jasig.portal.character.stream.CharacterEventReader;
import org.jasig.portal.character.stream.events.CharacterDataEvent;
import org.jasig.portal.character.stream.events.CharacterEvent;
import org.jasig.portal.character.stream.events.CharacterEventTypes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Top level class that initiates rendering via a {@link CharacterPipelineComponent}
 * 
 * @author Eric Dalquist
 * @version $Revision$
 */
public class DynamicRenderingPipeline implements IPortalRenderingPipeline {
    public static final String CHARACTER_SET = "UTF-8";
    public static final String DEFAULT_MEDIA_TYPE = "text/html";
    
    protected final Logger logger = LoggerFactory.getLogger(getClass());
    
    private CharacterPipelineComponent pipeline;

    /**
     * The root element in the rendering pipeline. This element MUST only return {@link CharacterEventTypes#CHARACTER}
     * type events.
     */
    public void setPipeline(CharacterPipelineComponent pipeline) {
        this.pipeline = pipeline;
    }

    @Override
    public void renderState(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        //Disable page caching
        res.setHeader("pragma", "no-cache");
        res.setHeader("Cache-Control", "no-cache, max-age=0, must-revalidate");
        res.setDateHeader("Expires", 0);

        final PipelineEventReader<CharacterEventReader, CharacterEvent> pipelineEventReader = this.pipeline.getEventReader(req, res);
        final String mediaType = getMediaType(pipelineEventReader);

        // set the response mime type
        res.setContentType(mediaType + "; charset=" + CHARACTER_SET);
        
        final PrintWriter writer = res.getWriter();
        
        for (final CharacterEvent event : pipelineEventReader) {
            if (CharacterEventTypes.CHARACTER != event.getEventType()) {
                throw new RenderingPipelineConfigurationException("Only " + CharacterEventTypes.CHARACTER + " events are supported in the top level renderer");
            }
            
            final String data = ((CharacterDataEvent)event).getData();
            writer.print(data);
            writer.flush();
            res.flushBuffer();
        }
    }

    /**
     */
    protected String getMediaType(final PipelineEventReader<CharacterEventReader, CharacterEvent> pipelineEventReader) {
        final String mediaType = pipelineEventReader.getOutputProperty(OutputKeys.MEDIA_TYPE);
        if (mediaType != null) {
            return mediaType;
        }

        this.logger.warn("No mediaType was specified in the pipeline output properties, defaulting to " + DEFAULT_MEDIA_TYPE);
        return DEFAULT_MEDIA_TYPE;
    }
}
